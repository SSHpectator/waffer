# waffer  ( WRITING THE README.md)

A lightweight Web Application Firewall (Waf) detection utility for passive and conservative active fingerprinting.

Warning: This project is for educational and defensive use only. Do not run active tests against systems you do not own or do not have explicit authorization to test.

Features

Passive fingerprinting using HTTP headers, cookies, status codes and response body patterns.

Optional conservative active tests (disabled by default) to increase detection confidence. ( WORKING ON IT )


Passive detection (normal GET/HEAD requests) is low risk but still generates traffic — respect robots.txt and rate limits.

This project is intended for security professionals, developers and researchers.

Contributing

Contributions are welcome! Suggested ways to help:

Add more reliable fingerprints (headers/cookies/body/status) for additional Waf vendors.

Improve scoring and reduce false positives.

Add async support with httpx and asyncio for scanning many targets.

Add unit tests and CI (GitHub Actions).

When contributing, please include tests for new fingerprints or behaviors.

License

This project is released under the MIT License. 

MIT License


Copyright (c) 2025 <SSHpectator>


Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:


[...]
Acknowledgements

Inspired by community fingerprinting projects and tools. Use responsibly.
