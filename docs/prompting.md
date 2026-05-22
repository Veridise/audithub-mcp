# Prompting

This file is a guide on how to effectively prompt an agent to use AuditHub.

## Uploading Projects

TODO

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
