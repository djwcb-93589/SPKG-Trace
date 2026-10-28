# Third-party notices

SPKG-Trace incorporates LibreLog-derived template-parsing components in
`src/spkg_workflow/librelog/vendor/`, integrated through workflow-specific input,
output, configuration, and model-client adapters. These components do not imply
that the entire SPKG-Trace method is an upstream LibreLog implementation.
Existing source headers are retained. An embedded private IP example was
anonymized; this is documented in the parser notice.

- `grouping.py` identifies the LogPAI team and the MIT license in its header.
- `llama_parser.py` and `regex_manager.py` are included as LibreLog-derived
  components. The project maintainers have confirmed permission for their public
  redistribution.

A license header in one file is not treated as a license grant for every file in
this project. This notice preserves attribution and does not assign a new blanket
license to SPKG-Trace or override third-party terms.

Dependencies retain their respective licenses and are installed separately.
