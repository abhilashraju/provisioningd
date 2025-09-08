# xyz.openbmc_project.Provisioning.Provisioning

Interface to represent the provisioning status of the BMC. Provides a property to indicate whether the BMC is provisioned, and methods to initiate provisioning and check the peer BMC connection.


## Methods
### StartProvisioning

Starts the provisioning process and updates the ProvisioningState accordingly.




### CheckPeerBMCConnection

Performs a check to determine if the peer BMC is reachable and and if already provisioned.


#### Parameters and Returns
| direction | name | type | description |
|:---------:|------|------|-------------|
| out | **unnamed** | boolean | True if the peer BMC is reachable and provisioned. false if peer BMC is not reachable or not-provisioned. |



## Properties
| name | type | description |
|------|------|-------------|
| **Provisioned** | boolean | True means the BMC is in a provisioned state. |

## Signals
No signals.

## Enumerations
No enumerations.

