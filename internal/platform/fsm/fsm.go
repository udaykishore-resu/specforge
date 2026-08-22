// Package fsm is the state machine engine every lifecycle in SpecForge runs on.
//
// The design goal is that state can only change through a declared transition.
// There is no `if status == "..."` branching in service code: a module declares
// its transition table once, the engine validates the table at init, and Fire is
// the only way to move.
//
// Each transition declares:
//
//   - the permitted source states and the target state
//   - the permission the caller must hold
//   - guards (pure predicates, evaluated in order, no side effects)
//   - effects (mutations, executed only after every guard passes)
//   - the domain event to emit and the audit action to record
//
// Guards being pure and effects being separate is what makes a transition
// safely retryable and makes the table itself reviewable as a security control.
package fsm

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/specforge/specforge/internal/platform/errors"
)

// State is a lifecycle state.
type State string

// Event names a transition trigger.
type Event string

func (s State) String() string { return string(s) }
func (e Event) String() string { return string(e) }

// Guard is a pure predicate. It must not mutate the subject or perform I/O.
// Returning a non-nil error blocks the transition and the error is surfaced to
// the caller, so the message should explain what precondition failed.
type Guard[T any] func(ctx context.Context, subject T) error

// Effect mutates the subject. Effects run inside the caller's transaction,
// in declaration order, only after every guard has passed.
type Effect[T any] func(ctx context.Context, subject T) error

// Transition declares one legal move.
type Transition[T any] struct {
	From        []State
	Event       Event
	To          State
	Permission  string // required permission, checked before guards
	Guards      []Guard[T]
	Effects     []Effect[T]
	EmitEvent   string // domain event type, e.g. "prd.approved"
	AuditAction string // audit action, e.g. "prd.approve"
	// Terminal marks a state from which no further transition is expected.
	Terminal bool
	// Description documents the business meaning; surfaced in generated docs.
	Description string
}

// Machine is a validated transition table.
type Machine[T any] struct {
	name        string
	initial     State
	transitions []Transition[T]
	index       map[key]*Transition[T]
	states      map[State]bool
	terminal    map[State]bool
}

type key struct {
	from  State
	event Event
}

// Definition describes a machine before validation.
type Definition[T any] struct {
	Name        string
	Initial     State
	States      []State
	Terminal    []State
	Transitions []Transition[T]
}

// New builds and validates a machine. It panics on an invalid table: a broken
// state machine is a programming error that must fail at startup, not at the
// first user request.
func New[T any](def Definition[T]) *Machine[T] {
	m, err := Build(def)
	if err != nil {
		panic(fmt.Sprintf("fsm: invalid machine %q: %v", def.Name, err))
	}
	return m
}

// Build validates a definition and returns the machine, or an error describing
// every problem found. Used by New and by the table-validation tests.
func Build[T any](def Definition[T]) (*Machine[T], error) {
	if def.Name == "" {
		return nil, errors.New("machine name is required")
	}
	if def.Initial == "" {
		return nil, errors.New("initial state is required")
	}

	m := &Machine[T]{
		name:        def.Name,
		initial:     def.Initial,
		transitions: def.Transitions,
		index:       make(map[key]*Transition[T], len(def.Transitions)*2),
		states:      make(map[State]bool, len(def.States)),
		terminal:    make(map[State]bool, len(def.Terminal)),
	}
	for _, s := range def.States {
		m.states[s] = true
	}
	for _, s := range def.Terminal {
		if !m.states[s] {
			return nil, fmt.Errorf("terminal state %q is not in the declared state set", s)
		}
		m.terminal[s] = true
	}
	if !m.states[def.Initial] {
		return nil, fmt.Errorf("initial state %q is not in the declared state set", def.Initial)
	}

	var problems []string
	for i := range def.Transitions {
		t := &def.Transitions[i]
		if t.Event == "" {
			problems = append(problems, fmt.Sprintf("transition %d has no event", i))
			continue
		}
		if !m.states[t.To] {
			problems = append(problems, fmt.Sprintf("transition %q targets undeclared state %q", t.Event, t.To))
		}
		if len(t.From) == 0 {
			problems = append(problems, fmt.Sprintf("transition %q has no source states", t.Event))
		}
		if t.AuditAction == "" {
			// Every transition changes governed state, so every transition must be
			// auditable. This is a hard requirement, not a style preference.
			problems = append(problems, fmt.Sprintf("transition %q declares no audit action", t.Event))
		}
		for _, f := range t.From {
			if !m.states[f] {
				problems = append(problems, fmt.Sprintf("transition %q sources undeclared state %q", t.Event, f))
				continue
			}
			if m.terminal[f] {
				problems = append(problems, fmt.Sprintf("transition %q leaves terminal state %q", t.Event, f))
			}
			k := key{from: f, event: t.Event}
			if _, dup := m.index[k]; dup {
				problems = append(problems, fmt.Sprintf("duplicate transition for (%s, %s)", f, t.Event))
				continue
			}
			m.index[k] = t
		}
	}

	// Reachability: every non-initial state must be the target of some transition,
	// and every non-terminal state must have a way out. An unreachable state or a
	// dead end is almost always a modelling mistake.
	reachable := map[State]bool{def.Initial: true}
	hasExit := map[State]bool{}
	for _, t := range def.Transitions {
		reachable[t.To] = true
		for _, f := range t.From {
			hasExit[f] = true
		}
	}
	for s := range m.states {
		if !reachable[s] {
			problems = append(problems, fmt.Sprintf("state %q is unreachable", s))
		}
		if !m.terminal[s] && !hasExit[s] {
			problems = append(problems, fmt.Sprintf("non-terminal state %q has no outgoing transition", s))
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, errors.New(strings.Join(problems, "; "))
	}
	return m, nil
}

// Name returns the machine's name.
func (m *Machine[T]) Name() string { return m.name }

// Initial returns the starting state.
func (m *Machine[T]) Initial() State { return m.initial }

// States returns every declared state, sorted.
func (m *Machine[T]) States() []State {
	out := make([]State, 0, len(m.states))
	for s := range m.states {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsTerminal reports whether s is a terminal state.
func (m *Machine[T]) IsTerminal(s State) bool { return m.terminal[s] }

// Lookup returns the transition for (from, event), if one is declared.
func (m *Machine[T]) Lookup(from State, ev Event) (*Transition[T], bool) {
	t, ok := m.index[key{from: from, event: ev}]
	return t, ok
}

// Can reports whether the transition exists, without evaluating guards.
func (m *Machine[T]) Can(from State, ev Event) bool {
	_, ok := m.Lookup(from, ev)
	return ok
}

// Allowed lists the events available from a state, sorted.
func (m *Machine[T]) Allowed(from State) []Event {
	var out []Event
	for k := range m.index {
		if k.from == from {
			out = append(out, k.event)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Outcome is the result of a successful transition.
type Outcome struct {
	From        State
	To          State
	Event       Event
	EmitEvent   string
	AuditAction string
	Permission  string
}

// PermissionChecker is supplied by the caller so the engine can enforce the
// declared permission without depending on the authorization package (which
// would invert the dependency direction).
type PermissionChecker func(ctx context.Context, permission string) error

// Fire executes a transition.
//
// Order of operations is deliberate and must not be changed:
//
//	permission -> guards (pure) -> effects (mutating)
//
// so that an unauthorised or invalid request cannot leave partial mutations
// behind, even if an effect later fails and the transaction rolls back.
func (m *Machine[T]) Fire(
	ctx context.Context,
	from State,
	ev Event,
	subject T,
	check PermissionChecker,
) (Outcome, error) {
	const op = "fsm.Fire"

	if !m.states[from] {
		return Outcome{}, errors.Invalid(op, "fsm.unknown_state",
			"%s is not a known state of %s", from, m.name)
	}

	t, ok := m.Lookup(from, ev)
	if !ok {
		allowed := m.Allowed(from)
		names := make([]string, len(allowed))
		for i, a := range allowed {
			names[i] = string(a)
		}
		e := errors.Precondition(op, "fsm.illegal_transition",
			"%q is not permitted from %s", ev, from)
		e.WithDetail("machine", m.name)
		e.WithDetail("from", string(from))
		e.WithDetail("allowed", names)
		return Outcome{}, e
	}

	if t.Permission != "" && check != nil {
		if err := check(ctx, t.Permission); err != nil {
			return Outcome{}, err
		}
	}

	for i, g := range t.Guards {
		if err := g(ctx, subject); err != nil {
			return Outcome{}, fmt.Errorf("fsm: %s guard %d on %q: %w", m.name, i, ev, err)
		}
	}

	for i, e := range t.Effects {
		if err := e(ctx, subject); err != nil {
			return Outcome{}, fmt.Errorf("fsm: %s effect %d on %q: %w", m.name, i, ev, err)
		}
	}

	return Outcome{
		From:        from,
		To:          t.To,
		Event:       ev,
		EmitEvent:   t.EmitEvent,
		AuditAction: t.AuditAction,
		Permission:  t.Permission,
	}, nil
}

// Mermaid renders the machine as a Mermaid state diagram, so documentation is
// generated from the executable table rather than maintained alongside it.
func (m *Machine[T]) Mermaid() string {
	var sb strings.Builder
	sb.WriteString("stateDiagram-v2\n")
	fmt.Fprintf(&sb, "    [*] --> %s\n", m.initial)

	type edge struct {
		from, to State
		ev       Event
	}
	var edges []edge
	for _, t := range m.transitions {
		for _, f := range t.From {
			edges = append(edges, edge{from: f, to: t.To, ev: t.Event})
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].from != edges[j].from {
			return edges[i].from < edges[j].from
		}
		return edges[i].ev < edges[j].ev
	})
	for _, e := range edges {
		fmt.Fprintf(&sb, "    %s --> %s : %s\n", e.from, e.to, e.ev)
	}
	for _, s := range m.States() {
		if m.terminal[s] {
			fmt.Fprintf(&sb, "    %s --> [*]\n", s)
		}
	}
	return sb.String()
}
