# Publishing Nobleson to Maven Central

This guide covers releasing `io.github.eselase-noble:nobleson-jwt` to Maven Central through the Sonatype Central Portal. You do the account, namespace, and GPG steps once; after that each release is a single `mvn deploy`.

The pom is already configured: it has the required metadata (name, description, url, license, developer, scm), it builds sources and javadoc jars, it uses the `central-publishing-maven-plugin`, and it signs artifacts under the `release` profile.

## One-time setup

### 1. Create a Central Portal account

Sign up at https://central.sonatype.com using your GitHub account. The old `oss.sonatype.org` (OSSRH) service is retired, so use the Portal.

### 2. Verify the namespace

In the Portal, add the namespace `io.github.eselase-noble`. Because it is an `io.github.<user>` name, the Portal verifies it by asking you to create a short-lived public GitHub repository whose name is a verification code it gives you. Create that repo, click verify, then delete it. The namespace is now yours.

If you later want the shorter `io.nobleson` namespace instead, you must own the `nobleson.io` domain and verify it with a DNS TXT record. Then change the `groupId` in `pom.xml`.

### 3. Create a publishing token

In the Portal, under your account, generate a user token. It gives you a username and a password. You will put these in `settings.xml` below.

### 4. Generate a GPG key

Central requires every artifact to be signed.

```bash
# generate a key (pick RSA 4096, no expiry or a long one)
gpg --full-generate-key

# find the key id
gpg --list-secret-keys --keyid-format=long

# publish the public key so Central can verify the signatures
gpg --keyserver keyserver.ubuntu.com --send-keys <YOUR_KEY_ID>
```

Keep the passphrase handy for the next step.

### 5. Put credentials in ~/.m2/settings.xml

```xml
<settings>
  <servers>
    <server>
      <id>central</id>
      <username>TOKEN_USERNAME_FROM_PORTAL</username>
      <password>TOKEN_PASSWORD_FROM_PORTAL</password>
    </server>
  </servers>

  <profiles>
    <profile>
      <id>release</id>
      <properties>
        <gpg.keyname>YOUR_KEY_ID</gpg.keyname>
        <gpg.passphrase>YOUR_GPG_PASSPHRASE</gpg.passphrase>
      </properties>
    </profile>
  </profiles>
</settings>
```

The server `id` must be `central`, matching `publishingServerId` in the pom.

## Releasing a version

1. Set the version you are releasing (no `-SNAPSHOT` for a real release):

   ```bash
   mvn versions:set -DnewVersion=0.1.0
   ```

   Also bump the `Version:` line in the per-file headers and the version in `README.md` so everything matches.

2. Build, sign, and deploy:

   ```bash
   mvn clean deploy -Prelease
   ```

   This runs the tests, builds the main, sources, and javadoc jars, signs them with GPG, and uploads the bundle to the Portal. Because `autoPublish` is `true`, a valid bundle is released automatically. If you prefer to review it first, set `autoPublish` to `false` in the pom and click publish in the Portal UI.

3. Tag the release in git and push the tag:

   ```bash
   git tag -a v0.1.0 -m "Nobleson JWT 0.1.0"
   git push origin v0.1.0
   ```

New artifacts usually appear on Central within a few minutes and are searchable at https://central.sonatype.com a bit later.

## Snapshots (optional)

If you want to share in-progress builds, give the version an `-SNAPSHOT` suffix and deploy the same way. Snapshots land in the Central snapshots repository rather than the release repository.

## JitPack, the zero-setup alternative

If you do not want to run the Central process, JitPack can build the library straight from a GitHub tag with no publishing on your side. Consumers add the JitPack repository and depend on `com.github.Eselase-Noble:jwt:<tag>`. See the README for the snippet. Pushing a new tag is all it takes.
