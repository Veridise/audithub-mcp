# Prompting

This file is a guide on how to effectively prompt an agent to use AuditHub.

## Uploading Versions

Requirements:
- Version creation must be enabled in your configuration
- In order to upload a source code version to AuditHub, you must have an
  existing configured organization and project set up in your configuration
  file.

To upload a project, run your agent in the root directory of your project
directory provide the following prompt:

```
Upload this directory as a new version in my NAME project on AuditHub.
The version name should be VERSION NAME.
```

## Running OrCa Tasks

TODO

## Running Vanguard Tasks

To run a Vanguard task, ask it to "execute Vanguard task run" and provide the
organization, project, and version IDs.
If you don't know the exact IDs, you can provide the name of the
organization/project and indicate "latest version", so the agent can look it up
for you.

Example prompt:

```
Execute Vanguard task run on "My Organization" org on the "Example Project" project.
Use all builtin detectors.
```

Example prompt with specific org, project:

```
Execute Vanguard task run with org 112 and project 734 on the latest version.
Run the reentrancy detector and all ERC20 custom detectors.
```
