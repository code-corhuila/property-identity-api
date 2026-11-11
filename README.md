# property-identity-api

> identity bounded context: service API

Part of the **Pms_Property** distributed system, Grupo 2. Governance and
documentation live in [`property-docs`](https://github.com/code-corhuila/property-docs).

Hexagonal service of the **identity** domain (the `UserAccount` and its `Role`), in
Java 21 and Spring Boot 3.5, as a three-module Maven build (ADR-011, Annex C). It is
the transversal security micro of Annex J.1.2: it will issue the JWT of people and
the service tokens of `property-workflow` and `property-worker`, and publish the
public key every service validates with (ADR-011, rule 4).

```
identity-core/       domain + application — NO Spring dependency
  domain/model/            entities, value objects, invariants and domain exceptions
  application/port/in/     what the service offers
  application/port/out/    what it needs
  application/usecase/     one use case per business operation
identity-adapters/   Spring Web and JDBC adapters
  adapter/in/http/         RS256 verifier, auth and correlation filters, error envelope, /health
  adapter/out/persistence/ the schema identity (JDBC); an in-memory twin only with PERSISTENCE=memory
identity-app/        Spring Boot application: the composition root
deploy/             Dockerfile and this service's compose file
```

**Why three modules.** `identity-core` does not declare Spring as a dependency, so
a `@Service` or `@Entity` in the domain **does not compile** (norm 5.3.3). The
dependency rule stops being a convention and becomes a build error.

The schema lives in `property-identity-db`; this service never migrates it. In the
platform it connects as `identity_app` (Annex J, ADR-008).

## Keys

Identity signs every token with RS256 and is the only service that holds the private
key (ADR-011, rule 4; `security-policy.md`). It needs both halves of the pair:

| Variable | Content |
|---|---|
| `JWT_PRIVATE_KEY` or `JWT_PRIVATE_KEY_FILE` | The private key, PKCS#8 PEM (`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`). Inline, one line with literal `\n`, as a `.env` file holds it; or the path of the `.pem` file |
| `JWT_PUBLIC_KEY` or `JWT_PUBLIC_KEY_FILE` | Its public key (`openssl pkey -pubout`), the same value every other service receives |

The service does not start without them, or when they are not one pair. `GET
/api/v1/jwks` publishes the public key with its `kid`. A key is never versioned.

## Run

```bash
mvn -B verify                                   # build and every test
mvn -B -DskipTests package
java -jar identity-app/target/identity-app-0.1.0.jar
```

Without Maven installed:

```bash
docker run --rm -v "$PWD":/app -w /app maven:3.9-eclipse-temurin-21 mvn -B verify
```

### Storage and the integration tests

The service stores accounts in the schema `identity`, connecting as `identity_app`
(`.env.example` lists the variables); without `DATABASE_URL` it does not start. The
in-memory adapters run only with `PERSISTENCE=memory`, set explicitly for the HTTP
tests or a local trial: never in an environment (norm 5.5.2). The integration tests run against the
real engine with the schema of `property-identity-db` applied, and only when
`TEST_DATABASE_URL` is set; otherwise they are skipped (Annex C). CI prepares that
database on every Pull Request. Locally, with `property-identity-db` cloned as a
sibling (or `IDENTITY_DB_DIR` pointing to it):

```bash
scripts/test-db.sh            # PostgreSQL 16 on 127.0.0.1:55432 with the identity schema
TEST_DATABASE_URL=jdbc:postgresql://localhost:55432/property TEST_DATABASE_USER=identity_app \
  TEST_DATABASE_PASSWORD=test-only mvn -B verify
scripts/test-db.sh down
```

The image:

```bash
docker build -f deploy/Dockerfile -t identity-api .
```

Inside the network `platform` the service is `http://identity-api:3004`; from
outside it is reached only through the gateway, at `http://localhost:8080/api/v1/register`,
`/login`, `/refresh`, `/logout`, `/jwks` and `/users`.

## Branching

Three permanent branches. **None of them accepts a direct commit** — you enter through a child
branch and leave through a Pull Request.

```
develop  <--PR--  feat/... fix/... chore/...
qa       <--PR--  hu-<story>-qa
main     <--PR--  release/...  hotfix/...
```

Promotion happens **by re-application** (`git cherry-pick -x`), never by merging one permanent
branch into another: `merge develop -> qa` and `merge qa -> main` do not exist in this model.

`main` requires **1 approval from `ariel5253`**. On `develop` and `qa` the team sets its own review
rule.

Full policy: `00-governance/branching-policy.md` and `00-governance/git-conventions.md` in
`property-docs`.
