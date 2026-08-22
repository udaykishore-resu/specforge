package server

import (
	"net/http"
	"strconv"
	"strings"

	artifactapp "github.com/specforge/specforge/internal/artifactgraph/app"
	artifactdomain "github.com/specforge/specforge/internal/artifactgraph/domain"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/httpx"
	"github.com/specforge/specforge/internal/platform/types"
)

type createLinkRequest struct {
	From       artifactRefDTO `json:"from"`
	To         artifactRefDTO `json:"to"`
	Type       string         `json:"link_type"`
	Origin     string         `json:"origin"`
	Confidence float64        `json:"confidence"`
	Rationale  string         `json:"rationale,omitempty"`
}

func (s *Server) handleCreateLink(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	body, _ := readBody(r, s.cfg.HTTP.MaxBodyBytes)
	var req createLinkRequest
	if err := httpx.DecodeJSON(w, r, &req, s.cfg.HTTP.MaxBodyBytes); err != nil {
		s.fail(w, r, err)
		return
	}
	linkType, err := types.ParseLinkType(req.Type)
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "link.type_invalid", "%s", err.Error()))
		return
	}
	origin := types.LinkOrigin(strings.ToUpper(req.Origin))
	if origin == "" {
		origin = types.OriginHuman
	}
	if !origin.Valid() {
		s.fail(w, r, errors.Invalid("server", "link.origin_invalid",
			"Link origin %q is not recognised.", req.Origin))
		return
	}
	confidence := req.Confidence
	if confidence == 0 && origin == types.OriginHuman {
		confidence = 1.0
	}

	s.idempotent(w, r, body, func() (int, any, error) {
		link, err := s.artifacts.CreateLink(r.Context(), artifactapp.LinkInput{
			TenantID: tenantID, ProjectID: projectID,
			From: types.ArtifactRef{
				ArtifactID: types.ArtifactID(req.From.ArtifactID), Version: req.From.Version,
			},
			To: types.ArtifactRef{
				ArtifactID: types.ArtifactID(req.To.ArtifactID), Version: req.To.Version,
			},
			Type: linkType, Origin: origin, Confidence: confidence, Rationale: req.Rationale,
		}, actor)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, linkDTO(link), nil
	})
}

func (s *Server) handleListLinks(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f := artifactapp.LinkFilter{
		TenantID: tenantID, ProjectID: projectID,
		Type:   types.LinkType(r.URL.Query().Get("link_type")),
		Status: types.LinkStatus(r.URL.Query().Get("status")),
		Limit:  intParam(r, "limit", 200),
	}
	if v := r.URL.Query().Get("from"); v != "" {
		id := types.ArtifactID(v)
		f.From = &id
	}
	if v := r.URL.Query().Get("to"); v != "" {
		id := types.ArtifactID(v)
		f.To = &id
	}

	links, err := s.artifacts.ListLinks(r.Context(), f, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]any, 0, len(links))
	for _, l := range links {
		out = append(out, linkDTO(l))
	}
	s.ok(w, r, http.StatusOK, map[string]any{"items": out})
}

type acceptLinkRequest struct {
	DispositionID string `json:"disposition_id,omitempty"`
}

func (s *Server) handleAcceptLink(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req acceptLinkRequest
	if r.ContentLength > 0 {
		if err := httpx.DecodeJSON(w, r, &req, s.cfg.HTTP.MaxBodyBytes); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	link, err := s.artifacts.AcceptLink(r.Context(), tenantID, projectID,
		types.LinkID(r.PathValue("linkID")), req.DispositionID, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusOK, linkDTO(link))
}

type rejectLinkRequest struct {
	Rationale string `json:"rationale"`
}

func (s *Server) handleRejectLink(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req rejectLinkRequest
	if err := httpx.DecodeJSON(w, r, &req, s.cfg.HTTP.MaxBodyBytes); err != nil {
		s.fail(w, r, err)
		return
	}
	link, err := s.artifacts.RejectLink(r.Context(), tenantID, projectID,
		types.LinkID(r.PathValue("linkID")), req.Rationale, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusOK, linkDTO(link))
}

// handleUpstream answers "what business requirement caused this?".
func (s *Server) handleUpstream(w http.ResponseWriter, r *http.Request) {
	s.traceQuery(w, r, artifactdomain.Upstream)
}

// handleDownstream answers "what implements this requirement?".
func (s *Server) handleDownstream(w http.ResponseWriter, r *http.Request) {
	s.traceQuery(w, r, artifactdomain.Downstream)
}

func (s *Server) traceQuery(w http.ResponseWriter, r *http.Request, dir artifactdomain.Direction) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	start, err := parseArtifactRef(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	var filter []types.ArtifactType
	if raw := r.URL.Query().Get("types"); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			t, perr := types.ParseArtifactType(strings.TrimSpace(part))
			if perr != nil {
				s.fail(w, r, errors.Invalid("server", "artifact.type_invalid", "%s", perr.Error()))
				return
			}
			filter = append(filter, t)
		}
	}

	var paths artifactdomain.Paths
	if dir == artifactdomain.Upstream {
		paths, err = s.artifacts.Upstream(r.Context(), tenantID, projectID, start, filter, actor)
	} else {
		paths, err = s.artifacts.Downstream(r.Context(), tenantID, projectID, start, filter, actor)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusOK, paths)
}

// handleImpact returns the deterministic impact set of a change.
func (s *Server) handleImpact(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	subject, err := parseArtifactRef(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	set, err := s.artifacts.Impact(r.Context(), tenantID, projectID, subject, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusOK, set)
}

func parseArtifactRef(r *http.Request) (types.ArtifactRef, error) {
	artifactID := r.URL.Query().Get("artifact")
	if artifactID == "" {
		return types.ArtifactRef{}, errors.Invalid("server.parseArtifactRef",
			"request.artifact_required", "An artifact query parameter is required.")
	}
	version := 1
	if v := r.URL.Query().Get("version"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return types.ArtifactRef{}, errors.Invalid("server.parseArtifactRef",
				"request.invalid_version", "The version must be an integer.")
		}
		version = n
	}
	return types.ArtifactRef{ArtifactID: types.ArtifactID(artifactID), Version: version}, nil
}

func linkDTO(l *artifactdomain.TraceLink) map[string]any {
	out := map[string]any{
		"link_id":    l.LinkID.String(),
		"from":       l.From,
		"to":         l.To,
		"link_type":  string(l.Type),
		"origin":     string(l.Origin),
		"confidence": l.Confidence,
		"status":     string(l.Status),
		"rationale":  l.Rationale,
		"created_by": l.CreatedBy.String(),
		"created_at": l.CreatedAt,
	}
	if l.DispositionID != nil {
		out["disposition_id"] = *l.DispositionID
	}
	return out
}
