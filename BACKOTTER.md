# rustic_core for BackOtter

This branch (`backotter`) is rustic_core with the patches that BackOtter's
rescue stick needs, kept on top of rustic_core's latest release. It is not a
separate project: the branch is rebased onto every new rustic_core release
rather than merged. rustic itself uses it through a `[patch.crates-io]` entry
on the `backotter` branch of github.com/mchobbit/rustic.

## What it adds

- The version reads `X.Y.Z+backotter.N`.

Planned: the metadata that BackOtter's restic (branch `backotter` of
github.com/mchobbit/restic) keeps as restic generic attributes, under the
same names and in the same form, so that either program restores what the
other backed up:

- `freebsd.file_flags`, `openbsd.file_flags`, `linux.inode_flags`
- `freebsd.acl_access`, `freebsd.acl_default`, `freebsd.acl_nfs4`,
  `freebsd.system_extattrs`
- `illumos.acl`, `illumos.system_attributes`

and the restore order that goes with them: ACLs after the mode, flags after
everything else.

## Moving to a new rustic_core release

    git fetch upstream --tags
    git rebase --onto rustic_core-vNEW rustic_core-vOLD backotter
    # set crates/core/Cargo.toml's version to "NEW+backotter.1"
    git push --force-with-lease origin backotter

Then move rustic's `backotter` branch to the rustic release that uses
rustic_core NEW (see BACKOTTER.md there).
