# Graph artifacts

The final workflow stage generates `06_knowledge_package/neo4j/` offline.
`nodes.jsonl` and `relationships.jsonl` are the authoritative import records.
CSV files mirror these records for inspection; their JSON property cells are not
native `neo4j-admin` import columns.

The directory also contains a manifest with file hashes, the compiled schema,
validation statistics, rejected records, constraints, parameterized query
references, and a standalone Python importer.

```sh
cd results/synthetic_auth/06_knowledge_package/neo4j
python import_neo4j.py
```

This validates integrity, IDs, properties, relationship endpoints, and counts;
it does not connect to Neo4j. Database import targets Neo4j 5.26 LTS and requires
the generated `requirements-import.txt`. Provide `NEO4J_URI`, `NEO4J_USERNAME`,
`NEO4J_PASSWORD`, and optionally `NEO4J_DATABASE` through private environment
configuration, then explicitly run `python import_neo4j.py --apply`.

Test first against an empty disposable database. Packages with rejected records
require explicit review and `--allow-rejected`. Batch transactions are not one
atomic package-wide transaction. Reimporting the same package uses stable IDs and
MERGE; changed input or rules create a new snapshot rather than deleting old data.

Each valid log retains a LogEvent with original text, field evidence, and canonical
values. MENTIONS edges retain field provenance. Business relationships are
event-specific. Default Process/Session observations are not inferred cross-log
entities. No year or time zone is invented. Structural validity and relationship
coverage are not semantic-accuracy measurements.
