#!/bin/sh
# seo_test.sh — the generated SEO files have to agree with the page.
#
# Every failure here is silent by nature: a sitemap naming last month's URL, a
# canonical that disagrees with the About box, a JSON-LD block truncated by an
# edit. Nothing renders differently, and the only symptom is a page that quietly
# stops being found.
#
#   sh scripts/seo_test.sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
gate="$root/scripts/seo.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/pqprobe-seo-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

pass=0; fail=0
ok()    { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
notok() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }

# fixture <dir> <canonical>
fixture() {
	d=$1 url=$2
	mkdir -p "$d"
	cat > "$d/index.html" <<HTML
<!doctype html>
<html lang="en">
<head>
<title>pqprobe — which classes of client can still handshake with this endpoint?</title>
<meta name="description" content="A description of the right sort of length for a search result, saying what the tool does.">
<meta name="robots" content="index, follow">
<link rel="canonical" href="$url">
<meta property="og:title" content="pqprobe">
<meta property="og:image" content="${url}assets/og-card.png">
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"SoftwareApplication","name":"pqprobe","url":"$url"}
</script>
</head>
<body><h1>pqprobe</h1></body>
</html>
HTML
	printf '0.9.9\n' > "$d/version"
}

run() { SEO_DIR="$1" SEO_VERSION="$(cat "$1/version")" sh "$gate" "$2" >/dev/null 2>&1; }

printf 'seo.sh render:\n'

fixture "$tmp/a" "https://example.test/pqprobe/"
run "$tmp/a" render || notok "render failed"

sitemap="$tmp/a/sitemap.xml"
if [ -f "$sitemap" ]; then ok "a sitemap is written"; else notok "no sitemap.xml"; fi
if grep -q "https://example.test/pqprobe/" "$sitemap" 2>/dev/null; then
	ok "the sitemap carries the canonical URL from the page, not a hardcoded one"
else
	notok "the sitemap does not name the page canonical"
fi
if grep -qE '<lastmod>[0-9]{4}-[0-9]{2}-[0-9]{2}</lastmod>' "$sitemap" 2>/dev/null; then
	ok "the sitemap has a dated lastmod"
else
	notok "no lastmod in the sitemap"
fi

robots="$tmp/a/robots.txt"
if grep -q "Sitemap: https://example.test/pqprobe/sitemap.xml" "$robots" 2>/dev/null; then
	ok "robots.txt points at the sitemap"
else
	notok "robots.txt does not point at the sitemap"
fi
if grep -q "Disallow:$" "$robots" 2>/dev/null || grep -q "Allow: /" "$robots" 2>/dev/null; then
	ok "robots.txt lets crawlers in"
else
	notok "robots.txt does not allow crawling"
fi

llms="$tmp/a/llms.txt"
if grep -q "pqprobe" "$llms" 2>/dev/null && grep -q "0.9.9" "$llms" 2>/dev/null; then
	ok "llms.txt names the tool and the version it describes"
else
	notok "llms.txt is missing the tool or the version"
fi

printf '\nseo.sh check:\n'

if run "$tmp/a" check; then ok "a rendered tree passes"; else notok "check failed on a fresh render"; fi

# The failure this gate exists for: the page moves and the sitemap does not.
fixture "$tmp/b" "https://example.test/pqprobe/"
run "$tmp/b" render
sed -i.bak 's|https://example.test/pqprobe/|https://example.test/moved/|' "$tmp/b/index.html"
if run "$tmp/b" check; then
	notok "a canonical that no longer matches the sitemap passed"
else
	ok "a canonical the sitemap does not name fails"
fi

fixture "$tmp/c" "https://example.test/pqprobe/"
run "$tmp/c" render
rm "$tmp/c/sitemap.xml"
if run "$tmp/c" check; then notok "a missing sitemap passed"; else ok "a missing sitemap fails"; fi

# The tags a search result is built from. Losing one is invisible on the page.
for tag in description robots canonical og:image; do
	fixture "$tmp/t-$tag" "https://example.test/pqprobe/"
	run "$tmp/t-$tag" render
	grep -v "$tag" "$tmp/t-$tag/index.html" > "$tmp/t-$tag/index.new"
	mv "$tmp/t-$tag/index.new" "$tmp/t-$tag/index.html"
	if run "$tmp/t-$tag" check; then
		notok "a page with no $tag passed"
	else
		ok "a page with no $tag fails"
	fi
done

# JSON-LD truncated by an edit is valid HTML and invisible in a browser.
fixture "$tmp/ld" "https://example.test/pqprobe/"
run "$tmp/ld" render
sed -i.bak 's|{"@context":"https://schema.org","@type":"SoftwareApplication","name":"pqprobe","url":"https://example.test/pqprobe/"}|{"@context":"https://schema.org","@type":"SoftwareApplication"|' "$tmp/ld/index.html"
if run "$tmp/ld" check; then
	notok "unbalanced JSON-LD passed"
else
	ok "JSON-LD whose braces do not balance fails"
fi

# Found while porting this gate to segcheck: its first sitemap listed
# running-in-containers.html, and Pages serves docs/ as committed — the .md is
# 200 and the .html 404s. A declared URL with nothing behind it wastes crawl
# budget on every crawl, which is the same reason the host root only lists
# sitemaps that answer 200. pqprobe's sitemap holds one URL today; the gate is
# here so the second one cannot arrive broken.
printf '\nseo.sh check — every URL in the sitemap has to exist:\n'

fixture "$tmp/ghost" "https://example.test/pqprobe/"
run "$tmp/ghost" render
sed -i.bak 's|<loc>https://example.test/pqprobe/</loc>|<loc>https://example.test/pqprobe/</loc>\n  </url>\n  <url>\n    <loc>https://example.test/pqprobe/nowhere.html</loc>|' "$tmp/ghost/sitemap.xml"
if run "$tmp/ghost" check; then
	notok "a sitemap URL with no file behind it passed"
else
	ok "a sitemap URL with no file behind it fails"
fi

fixture "$tmp/real" "https://example.test/pqprobe/"
printf 'x' > "$tmp/real/extra.html"
run "$tmp/real" render
sed -i.bak 's|<loc>https://example.test/pqprobe/</loc>|<loc>https://example.test/pqprobe/</loc>\n  </url>\n  <url>\n    <loc>https://example.test/pqprobe/extra.html</loc>|' "$tmp/real/sitemap.xml"
if run "$tmp/real" check; then
	ok "a sitemap URL whose file exists passes"
else
	notok "a real file was rejected"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
