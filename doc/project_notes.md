# Project Notes

## Certificate generation flow
1. Keys are generated:
   - By the customer
   - By the platform
2. A request is made:
   - A certificate template is selected, this will mandate everything except the subjectName and SAN
   - The CA is selected, or is set to be self-signed
   - The request is sent via a CSR. Two options:
      - The original request included a CSR
      - A CSR is generated using a JSON that contains subjectName and SAN, keys are generated as part of the request
3. The certificate is signed:
   - A TBS Certificate is generated using the template and request details.
   - The TBS Certificate is signed with a dummy key
   - The final certificate is generated signed with the appropriate key

