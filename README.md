# ATT&CK® for IR Reporting

## Introduction
[MITRE ATT&CK®](https://attack.mitre.org/) provides a vast amount of information, not only on (sub-)techniques observed by perpetrators but also on mitigations and detections to deploy in the environment to either avoid or detect the applied (sub-)techniques being successful or at least being downgraded or hampered. 

This project aims to generate in an automated way the core documents assembling the available information from the MITRE ATT&CK® framework without the need to sift through the online resources. This can be done whenever a set of ATT&CK® (Sub-)Techniques are identified during the report writing as a deliverable for an incident response engagement. [CISA's Decider](https://github.com/cisagov/decider) may help identifiying the relavant ATT&CK® (Sub-)Techniques.

We believed that providing recommendations based on the observed (Sub-)Techniques may prove to be useful for the customer in order to focus on the actions that could be performed to improve the security posture of their environment. By coupling these with the [CIS Security Controls](https://www.cisecurity.org/controls) and/or the [NIST 800-53 Rev 5 Controls](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf), the idea was to provide the CISO, Head of IT or anyone responsible and/or accountable for the security of the environment the established industry references,  leverage, and support to perform these improvements.

With the same approach in mind, providing detections based on the observed (Sub-)Techniques may prove to be useful in covering the gaps where mitigations are incomplete or not possible for a variety of reasons. The addition with the information available from [OSSEM-DM](https://github.com/OTRF/OSSEM-DM) provides tangible hooks for a detection engineer to build upon.

Lastly, wze conclude the full circle by providing freely available tests from [Atomic Red Team™](https://github.com/redcanaryco/atomic-red-team) as a focused means to validate the security implementations.

We also believe that leveraging other MITRE ATT&CK related projects, such as [CTID ATT&CK® Flow](https://github.com/center-for-threat-informed-defense/attack-flow) and [MITRE ATT&CK® Navigator](https://mitre-attack.github.io/attack-navigator/), improves the way of communicating the events from an incident at different target audience levels at the customer's organisation.

The last part handles the generation of sightings according to the [sightings model](https://github.com/center-for-threat-informed-defense/sightings_ecosystem).

This project makes use of MITRE ATT&CK® - [ATT&CK® Terms of Use](https://attack.mitre.org/resources/terms-of-use/).

## Powershell Module

| [Recommendations](module/AttackIrReporting.psm1#L499) | [CTID ATT&CK® Flow](module/AttackIrReporting.psm1#L1432) | [ATT&CK® Navigator Layer](module/AttackIrReporting.psm1#L1799) | [Sightings](module/AttackIrReporting.psm1#L1930) |
| ------------------------------------------------------------------------------------------------------------ | ----------------------------- | ---------------------------------------------- | ---------------------------------------------- |

## Documentation

### Recommendations

- Function: [New-ATTACKRecommendations](docs/index.md#New-ATTACKRecommendations)
- Aim: Generating in an automated way DOCX or TXT documents presenting the collected information across the ATT&CK® knowledge base, combined with CIS Controls, NIST 800-53 Controls, OSSEM-DM information, and Atomic Red Team™ enabling the analysts to add complementary recommendations.
- Requires: List of identified ATT&CK® (Sub-)Techniques, ATT&CK® Navigator Layer or CISA Decider Export
- Delivers: DOCX or TXT files ready to use

### CTID ATT&CK® Flow

- Function: [New-CTIDATTACKFlow](docs/index.md#New-CTIDATTACKFlow)
- Aim: Generating a headstart AFB ATT&CK® Flow Builder file including Actions and possibly Assets enabling the analysts to visualise the flow of events.
- Requires: Identified ATT&CK® (Sub-)Technique/Tactic pairs, ATT&CK® Navigator Layer or CISA Decider Export, and optionally a list of assets.
- Delivers: AFB file to be used with [CTID ATT&CK® Flow Builder](https://center-for-threat-informed-defense.github.io/attack-flow/ui/)

### ATT&CK® Navigator Layer

- Function: [New-ATTACKNavigatorLayer](docs/index.md#New-ATTACKNavigatorLayer)
- Aim: Generating a JSON ATT&CK® Navigator Layer from the identified (Sub-)Techniques/Tactic pairs leveraging the use of Navigator Layers in the different use cases.
- Requires: Identified ATT&CK® (Sub-)Technique/Tactic pairs
- Delivers: JSON file to be used with [MITRE ATT&CK® Navigator](https://mitre-attack.github.io/attack-navigator/)

### Sightings

- Function: [New-ATTACKSighting](docs/index.md#New-ATTACKSighting)
- Aim: Generating JSON Direct Technique/Software Sightings from the identified (Sub-)Techniques providing a means to exchange this information with [CTID](CTID@MITRE-Engenuity.org) (or other entities).
- Requires: Identified ATT&CK® (Sub-)Techniques and optionally a list of used [software](https://attack.mitre.org/software/)
- Delivers: JSON file including the required sightings information.


Personal Note
- All scripts were developed as an initiative within Check Point Incident Response Team and are provided as is. 
- These scripts may need cleaning up and adhere to proper code conventions, yet I'm no coder. - Sorry.
