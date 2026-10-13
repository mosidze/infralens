# Third-party components

| Component | Where | Licence |
|---|---|---|
| [Cytoscape.js](https://js.cytoscape.org) 3.26 | embedded in the interactive report (`internal/report/assets/cytoscape.min.js`); its copyright and licence notice stays at the top of that file and of every generated `report.html` | MIT, © The Cytoscape Consortium |
| AWS SDK for Go v2 and smithy-go | linked into the binary | Apache-2.0 |
| golang.org/x/sync | linked into the binary | BSD-3-Clause |

`go.sum` pins the exact versions of everything linked in.

This project is licensed under the Apache License 2.0; see `LICENSE` and `NOTICE`.
