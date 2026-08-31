# Engineer4Me Phase 9 Step 283 — Python Parse-Error Qualification

**Qualification ID:** `930b71d8ed60fbdf87eff3d12b4be8ed8e457309a95f9b049de174bc072d9691`
**Source commit:** `d37e74f8b0855fdf2432ed6c78566c0adadd2590`
**Status:** Controlled static-source qualification; no backend source repair authorized or required.

## Finding

The four Step 281 parser findings are valid UTF-8-BOM Python sources. Each exact committed blob compiles when supplied as bytes and produces the same AST after encoding-aware `utf-8-sig` decoding. The inventory error arose after plain UTF-8 decoding exposed U+FEFF to string-based AST parsing.

## Exact qualified files

| Path | Committed bytes | Committed SHA-256 | BOM-removed projection SHA-256 | Source change required |
| --- | --- | --- | --- | --- |
| `backend/app/engineering/knowledge_repository.py` | 23553 | `cd4b525ad570fcf9bc47ca06ce1c10f9f0076c3d78fa9333c808903f54dda780` | `1d5bb1c73763a1a58361874613f05b71275cffe4e81a604b12fecefa6f1d214e` | No |
| `backend/app/engineering/knowledge_service.py` | 18924 | `d8af1f1abf2d3c52c74a460a67df550bcd8d3bea44226c7b45d970399575ea60` | `c35dabbb65e560007bf4dda46b1ef86c9560a221147cbef1d80802125003ca5b` | No |
| `backend/app/ingestion/ingestion_job_models.py` | 17569 | `b347eaa8655c5eeead68f7a67c5cc06c6e0c09601d82abc4848c03a585b4844b` | `e6ce2c5c3b7ca8005671b611fd3e90aa08e4a88df44f6b6c14587dbf03d33388` | No |
| `backend/app/ingestion/ingestion_job_service.py` | 36841 | `fe8e2b4df4c6e72f8e7b7b3fe56a074a45cc188b45dca76c5180f6a38ba8092a` | `2b4078e48fe21c73c9a990d5e8c9c41a8118e7c163c8221a164b17cf69687954` | No |

## Disposition

- No backend source file is changed by Batch 282–286.
- The findings are disposed for Phase 9 planning as an analyzer decoding limitation, not a backend route or runtime defect.
- Future Python source analyzers must use encoding-aware decoding or compile source bytes directly.
- No application module was imported or executed during qualification.
