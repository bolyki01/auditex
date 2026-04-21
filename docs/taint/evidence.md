# Evidence

## Repo-internal evidence

Primary source records:
- removed `docs/research/steal-backlog.md`
- removed `docs/research/repo-cards.md`
- removed legacy source-review module

These records explicitly map upstream repos to intended `auditex` ports.

Most important entries:
- `ThomasKur/M365Documentation`
  - friendly-name translation map
  - section registry
  - format-split writers
- `System-Admins/m365assessment`
  - review template registry
  - overview-detail HTML split

## Upstream license evidence

Local competitor mirror path:
- `~/dev/library/auditex/competitors/repos/`

Observed there:
- `ThomasKur__M365Documentation/LICENSE`
  - `GPLv3`
- `System-Admins__m365assessment`
  - no visible `LICENSE` file found
- `maester365__maester/LICENSE`
  - `MIT`
- `microsoft__EntraExporter/LICENSE`
  - `MIT`
- `dirkjanm__ROADtools/LICENSE`
  - `MIT`
- `CompliantSec__M365SAT/LICENSE`
  - `MIT`
- `cisagov__ScubaGear/LICENSE`
  - `CC0-1.0`

## External license references used for remediation

- GitHub licensing docs
  - <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository>
  - basis used here: no license means default copyright remains with the author
- GNU GPLv3
  - <https://www.gnu.org/licenses/gpl-3.0.html>
  - basis used here: derivative covered work is not a fit for a proprietary ship target
- OSI MIT license
  - <https://opensource.org/license/mit>
  - basis used here: commercial use is allowed if the notice is kept

## Limits

This folder does **not** prove line-by-line copying.

It proves this much:
- repo records previously targeted upstream reuse
- two targeted upstreams are bad for a proprietary ship target
- the mapped product surfaces were rewritten in the current tree

For legal cleanup later, this folder is the starting map.
