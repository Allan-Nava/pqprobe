package main

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Allan-Nava/pqprobe/internal/verdict"
)

// Completions and the man page are generated from the flag set and from the
// same help text the binary prints (PQ-57).
//
// Nothing here is a second copy of anything. PQ-40 is the precedent and the
// reason: a flag declared in one place and documented in another drifts
// silently, and the two-way test that caught that only covered --help. A test
// walks the FlagSet against every artefact produced here, so a new flag cannot
// ship half-visible.

// completionShells is what `pqprobe completion` accepts, in the order the help
// lists them.
func completionShells() []string { return []string{"bash", "zsh", "fish"} }

// commands is the subcommand list, which is short enough to be worth completing
// and long enough that nobody remembers `profiles` is plural.
func commands() []string {
	return []string{"probe", "profiles", "explain", "version", "completion", "man", "help"}
}

// probeFlagNames is every flag the probe declares, sorted, as they are written.
func probeFlagNames() []string {
	fs, _ := newProbeFlags()
	var out []string
	fs.VisitAll(func(f *flag.Flag) { out = append(out, "--"+f.Name) })
	sort.Strings(out)
	return out
}

// explainWords is the vocabulary `explain` answers for: the classes and the
// topics. Completing it is most of the value of completing anything here — the
// words are hyphenated, similar, and read off a report under pressure.
func explainWords() []string {
	var out []string
	for _, c := range verdict.Classes() {
		out = append(out, string(c))
	}
	out = append(out, verdict.Topics()...)
	return out
}

func completionTo(w io.Writer, args []string) int {
	shell := ""
	if len(args) > 0 {
		shell = strings.TrimLeft(args[0], "-")
	}
	known := false
	for _, s := range completionShells() {
		if s == shell {
			known = true
		}
	}
	if !known {
		fmt.Fprintf(w, "pqprobe: %q is not a shell pqprobe generates completions for. These are: %s\n",
			shell, strings.Join(completionShells(), ", "))
		return 2
	}

	cmds := strings.Join(commands(), " ")
	flags := strings.Join(probeFlagNames(), " ")
	words := strings.Join(explainWords(), " ")

	switch shell {
	case "bash":
		fmt.Fprintf(w, `# pqprobe bash completion — eval "$(pqprobe completion bash)"
_pqprobe() {
	local cur prev cmds flags words
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"
	cmds="%s"
	flags="%s"
	words="%s"
	case "$prev" in
	explain)      COMPREPLY=( $(compgen -W "$words" -- "$cur") ); return ;;
	--exit-on)    COMPREPLY=( $(compgen -W "OK WARN BAD ERROR $words" -- "$cur") ); return ;;
	--min-severity) COMPREPLY=( $(compgen -W "OK WARN BAD ERROR" -- "$cur") ); return ;;
	completion)   COMPREPLY=( $(compgen -W "%s" -- "$cur") ); return ;;
	esac
	if [ "$COMP_CWORD" -eq 1 ]; then
		COMPREPLY=( $(compgen -W "$cmds" -- "$cur") ); return
	fi
	case "$cur" in
	-*) COMPREPLY=( $(compgen -W "$flags" -- "$cur") ) ;;
	*)  COMPREPLY=( $(compgen -f -- "$cur") ) ;;
	esac
}
complete -F _pqprobe pqprobe
`, cmds, flags, words, strings.Join(completionShells(), " "))

	case "zsh":
		fmt.Fprintf(w, `#compdef pqprobe
# pqprobe zsh completion — pqprobe completion zsh > "${fpath[1]}/_pqprobe"
_pqprobe() {
	local -a cmds flags words
	cmds=(%s)
	flags=(%s)
	words=(%s)
	if (( CURRENT == 2 )); then
		_describe 'command' cmds
		return
	fi
	case "${words[CURRENT-1]}" in
	explain)                 _values 'class or topic' ${words}; return ;;
	--exit-on)               _values 'status or class' OK WARN BAD ERROR ${words}; return ;;
	--min-severity)          _values 'status' OK WARN BAD ERROR; return ;;
	completion)              _values 'shell' %s; return ;;
	esac
	_alternative "flags:flag:(${flags})" 'files:file:_files'
}
_pqprobe "$@"
`, cmds, flags, strings.Join(explainWords(), " "), strings.Join(completionShells(), " "))

	case "fish":
		fmt.Fprintln(w, "# pqprobe fish completion — pqprobe completion fish > ~/.config/fish/completions/pqprobe.fish")
		for _, c := range commands() {
			fmt.Fprintf(w, "complete -c pqprobe -n __fish_use_subcommand -a %s\n", c)
		}
		for _, f := range probeFlagNames() {
			fmt.Fprintf(w, "complete -c pqprobe -l %s\n", strings.TrimPrefix(f, "--"))
		}
		fmt.Fprintf(w, "complete -c pqprobe -n '__fish_seen_subcommand_from explain' -a '%s'\n", words)
		fmt.Fprintf(w, "complete -c pqprobe -n '__fish_seen_subcommand_from completion' -a '%s'\n",
			strings.Join(completionShells(), " "))
		fmt.Fprintf(w, "complete -c pqprobe -l exit-on -a 'OK WARN BAD ERROR %s'\n", words)
		fmt.Fprintln(w, "complete -c pqprobe -l min-severity -a 'OK WARN BAD ERROR'")
	}
	return 0
}

// manTo writes the man page, in roff, from the same help text the binary prints
// — `pqprobe man > /usr/local/share/man/man1/pqprobe.1`.
//
// The body is the help output, indented as a literal block rather than
// reformatted: it is already the reference an operator reads, and a second
// wording of it is a second thing to keep true.
func manTo(w io.Writer) int {
	var help strings.Builder
	usageTo(&help)

	fmt.Fprintf(w, ".TH PQPROBE 1 \"\" \"pqprobe %s\" \"pqprobe\"\n", version)
	fmt.Fprint(w, `.SH NAME
pqprobe \- which classes of client can still handshake with this endpoint
.SH SYNOPSIS
.B pqprobe probe
.IR target ...
.RI [ flags ]
.br
.B pqprobe profiles
.br
.B pqprobe explain
.RI [ class | topic ]
.br
.B pqprobe version
.RB [ --short ]
.SH DESCRIPTION
pqprobe dials one TLS endpoint with several deliberately different client
shapes and reports which classes of client can still complete a handshake with
it, and how it refuses the others. It sends no application data: a handshake
and a close, plus a
.B --starttls
negotiation where a port needs one.
.PP
The interesting result is never a single failure but the asymmetry: a classical
client connects and a post-quantum-capable one does not, which is an origin
every existing health check calls healthy while a CDN in front of it serves
errors.
.SH OPTIONS
.nf
`)
	fmt.Fprint(w, roffEscape(help.String()))
	fmt.Fprint(w, `.fi
.SH EXIT STATUS
.TP
.B 0
the probe ran \- findings are output, not an error
.TP
.B 1
.B --exit-on
matched: the status threshold, or the named class
.TP
.B 2
usage error, or no target could be parsed
.SH SEE ALSO
.B pqprobe explain
.RI < class >
prints what a class means, whom it affects and what to do, with no network call.
.SH AUTHOR
Allan Nava. Source and issues: https://github.com/Allan-Nava/pqprobe
`)
	return 0
}

// roffEscape protects the two sequences roff reads as markup: a leading dot
// starts a request, and a backslash starts an escape. Everything else in the
// help text is ordinary.
func roffEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\e`)
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, ".") || strings.HasPrefix(line, "'") {
			b.WriteString(`\&`)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}
