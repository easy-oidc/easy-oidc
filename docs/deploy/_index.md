---
title: Deploy
weight: 4
---

Choose where to run a persistent Truster issuer. The official
OpenTofu/Terraform modules provision the cloud infrastructure and pass the same
Truster application settings to each deployment.

- [Local development and testing](/docs/deploy/local/) - Run a quick demo or a reusable localhost issuer
- [AWS deployment guide](/docs/deploy/aws/) - Deploy a persistent issuer on EC2
- [Google Cloud deployment guide](/docs/deploy/google/) - Deploy a persistent issuer on Compute Engine
- [Kubernetes deployment guide](/docs/deploy/kubernetes/) - Install the official OCI image and Helm chart

Additional references:
- [Application configuration](/docs/config/)
- [AWS module and complete input reference](https://github.com/truster-dev/terraform-aws-truster#variables)
- [Google Cloud module and complete input reference](https://github.com/truster-dev/terraform-google-truster#variables)
