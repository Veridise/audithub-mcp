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

```text
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

Example prompt that runs a custom detector:

```
Execute Vanguard task run with org 112 and project 734 on the latest version.
Create and run a custom detector that searches for all calls to `approve(address,uint256)`.
```

## Retrieving and Triaging Findings

After running a tool task that reports findings, you can prompt the agent to
automatically retrieve the findings and triage them locally (categorize as
confirmed bug or false alarm).

Assumptions:
- The task has already finished, and you know the task ID before-hand.
- The prompt should have enough information to identify the project and organization of the task.

```text
Retrieve the findings from the logs of each step of task X, in project Y and organization Z.
Fetch the logs from the task and parse the findings.
Triage the reported findings by confirming against the project source code.
```

NOTE: currently, `ah-mcp` does not provide a way to directly obtain findings information
(as shown in the "Findings" table in the web interface).
We plan on simplifying the prompting method in the future.

## End-to-End Example

The following prompt template demonstrates how to upload a project, run a DeFi Vanguard
task, and automatically retrieve and triage the results.

```text
Upload this directory as a new version in my AuditHub organization's project.
The version name should be "version-N" where "N" is one more than the largest number of the existing versions.
Confirm immediately before the upload is performed.

Then execute a DeFi Vanguard V2 task with all built-in detectors on the uploaded version.
Confirm before executing the task.

Lastly, retrieve task logs for the detector steps and parse the findings.
Write each full finding title and description to a `./audithub/findings/<task_id>.md` file.

Triage the reported findings by confirming against the project source code.
```
