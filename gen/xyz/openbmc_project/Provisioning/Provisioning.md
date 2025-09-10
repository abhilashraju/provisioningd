# xyz.openbmc_project.Provisioning.Provisioning

Interface to represent the provisioning status of the BMC. Provides a property to indicate whether the BMC is provisioned, and methods to initiate provisioning and check the peer BMC connection.


## Methods
### ProvisionPeer

Starts the provisioning process on the peerBmc .




### InitiatePeerConnectionTest

starts an mTLS connection attempt to the peer BMC. This method only initiates the handshake and returns immediately; the result (success/failure) must be reflected by the daemon by updating the PeerConnected property.





## Properties
| name | type | description |
|------|------|-------------|
| **Provisioned** | boolean | True means the BMC is in a provisioned state. |
| **PeerConnected** | boolean | True if a peer BMC is present and detected on the network. False if no peer BMC is present or not connected. |

## Signals
### PeerProvisioned

Emitted when the ProvisionPeer method completes. The signal carries a boolean indicating whether provisioning on the peer succeeded or failed.




## Enumerations
No enumerations.

