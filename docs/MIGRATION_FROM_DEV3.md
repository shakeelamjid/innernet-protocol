# Safe migration from deployed RC5 dev3 to v1.0.0 scoped core

**GitHub release workflow: one `main` branch only.** This source update is separate from deploying production containers.

1. Preserve the deployed RC5 dev3 container image/digest, database backups and current configuration. **Do not redeploy Contabo automatically** when updating GitHub.
2. In GitHub Desktop, select the existing `innernet-protocol` repository on `main`, fetch/pull to ensure it is up to date, then apply the packaged source update. Do not create a separate branch or force-push.
3. Review the changes, commit and push using GitHub Desktop. The removed historical files remain in Git history; the latest working tree is the streamlined release source.
4. Require GitHub Actions to pass for this exact `main` commit: Python 3.11/3.12 tests, release manifest, Go UV10 vectors and Docker/Coolify image builds. **Only then** create the `v1.0.0` tag and GitHub Release.
5. Test installation on Mac and Linux, and execute a synthetic ST81/OB80-2 transfer; do not rely on previous dev3 WAN evidence for the new build.
6. Test SQLite/backfill migration against a **copy** of existing data, never the live original. Verify checkpoint hashes and storage limits.
7. HTTP-v3 integrations must stop passing `capability_pair=` and use the fresh-capability persistence callback; never reuse an `inn3_` encryption root for different objects.
8. Run isolated native-WAN and cross-host R90 tests on the new build before planning a separately approved, backed-up production deployment.

This is a source release, not a backup of operational secrets, Docker volumes or Contabo runtime data. Public release additionally requires a secret scan of the **full previous Git history**.
