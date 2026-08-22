7. Rekey Relay

crypto-lab-rekey-relay · ENCRYPTION

Thesis. A semi-trusted proxy transforms Alice's ciphertext into Bob's without learning the plaintext — and in the obvious construction, the proxy and Bob together recover Alice's private key in one division.

Construction. Two schemes, in order. BBS98 (Blaze–Bleumer–Strauss 1998), ElGamal-based, bidirectional, rk_{A→B} = b/a — simple, and broken in a way worth showing. Then AFGH (Ateniese–Fu–Green–Hohenberger, NDSS 2005 / TISSEC 2006), pairing-based, unidirectional, collusion-resistant. Third reuse of the BLS12-381 code, so it is cheap by the time you get here.

Acts
Delegate. Alice encrypts to herself, generates rk_{A→B}, hands it to the proxy. Proxy transforms. Bob decrypts. A persistent proxy-view panel shows ciphertext only, at every step.
Collusion — the attack. Under BBS98 the proxy holds b/a and Bob holds b. Divide. Alice's private key falls out. COLLUSION_KEY_RECOVERED.
The fix. Switch to AFGH, repeat the collusion, nothing usable emerges. Show which term prevents it and why unidirectionality buys this.
One hop only. AFGH re-encrypts level-2 to level-1, and level-1 cannot be re-encrypted again. Try it. ALREADY_REENCRYPTED.
Delegation graph. The proxy never sees plaintext and always sees who delegates to whom. For many deployments that metadata is the sensitive part.

Negative claim (NEG-1). These static constructions provide no cryptographic revocation of an already-issued re-encryption capability. Deleting rk only works if the proxy cooperates; absent that, Alice must rotate her key and re-encrypt — the thing PRE was adopted to avoid. Scope the claim to the two schemes on the page: conditional and time-based PRE schemes designed with revocation do exist, and THREAT-MODEL.md should name them rather than implying the limitation is inherent to PRE.

Failure codes. RK_MISMATCH · ALREADY_REENCRYPTED · WRONG_LEVEL · COLLUSION_KEY_RECOVERED · MALFORMED_RK

Repo description.

Browser demo: a proxy re-encrypts Alice's ciphertext for Bob without seeing plaintext — then Bob and the proxy collude under BBS98 and divide out Alice's private key. AFGH fixes the collusion; neither fixes un-delegating.