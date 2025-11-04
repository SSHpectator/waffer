# waffer

Waffer is a Web Application Firewall (WAF) detection utility for passive and active active WAF fingerprinting.

Warning: This project is for educational and defensive use only. Do not run active tests against systems you do not own or do not have explicit authorization to test.

## How WAF detection is performed

Passive WAF fingerprinting using HTTP headers, cookies, status codes and response body patterns of known WAF.
Passive detection are performed with HEAD/GET requests.

## Future update
In the future there will be an active detection method, which will be disabled by default, to increase detection confidence. ( WORKING ON IT )

This project is intended for security professionals, developers and researchers.

## Contributing

Contributions are welcome! 
Contributors will be displayed in a contributor list!
<br>

- Suggested ways to help:

  - Add more reliable fingerprints (headers/cookies/body/status) for additional Waf vendors.

  - Improve scoring and reduce false positives.

  - Add async support with httpx and asyncio for scanning many targets.

  - Add unit tests and CI (GitHub Actions).

When contributing, please include tests for new fingerprints or behaviors.

## License

This project is released under the MIT License. 

## MIT License

Copyright (c) 2025 <SSHpectator>


Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
 - Non-Authorized scanning. 

## Acknowledgements
Tool built by an hacker, helped by hackers, for hackers. Use responsibly!
