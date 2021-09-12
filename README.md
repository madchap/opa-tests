OPA policies to fail if `severity` is Critical or CVSS 3.x score is 9.0 for some quick test.

* Generate grype json output for an arbitrary image
`grype -o json gcr.io/distroless/java:11 > grype-distroless-java-11-vulns.json`

* Generate JSON file schema (used https://extendsclass.com/json-schema-validator.html)
This allows to catch typos when writing rego and trying keys that do not exist.

* Run `opa eval`
```
opa eval --input grype-distroless-java-11-vulns.json --data critical.rego --schema grype-json-schema.json "data.vulnpolicy"

{
  "result": [
    {
      "expressions": [
        {
          "value": {
            "allow": false,
            "violation": [
              "CVE-2021-33574",
              "CVE-2021-35942",
              "CVE-2019-1010022"
            ]
          },
          "text": "data.vulnpolicy",
          "location": {
            "row": 1,
            "col": 1
          }
        }
      ]
    }
  ]
}

```

