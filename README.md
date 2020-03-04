###Validation and Mutating Webhooks

This project provides a single image and Helm chart that does the following:
1. Image contains both an admission and mutating webhook to ensure A) No privileged escalation in pods or deployments and B) the container runs as a random UID that is in the 'root' (0) group.
    * With a single image, it is a single Kubernetes service that the webhooks can refer to.
2. The helm chart deploys both the validation and mutating webhooks into your environment.
    * It also manages the certificates required for TLS communication to the validation/mutating container.
    
    


