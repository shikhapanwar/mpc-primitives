/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2017 MPC-PRIMITIVES ()
* This file is part of the MPC-PRIMTIVES project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on MPC-PRIMTIVES contain an appropriate citation to MPC-PRIMITIVES, including a reference to
* 
* 
* MPC-PRIMITIVES uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://raw.githubusercontent.com/cris-iisc/mpc-primitives/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


#pragma once

/**
* Many cryptographic primitives and schemes have different security levels.
* For example, an encryption scheme can be CPA-secure (secure against chosen-plaintext attacks)
* or CCA-secure (secure against chosen-ciphertext attacks).
* The security level of a cryptographic entity is specified by making the implementing class of the entity
* declare that it implements a certain security level; for example, an encryption scheme that is CCA-secure will implement the Cca interface.
* Different primitives have different families that define their security levels (e.g., hash functions, MACs, encryption).
* It is often the case that different security levels of a given primitive form a hierarchy (e.g., any CCA-secure encryption scheme is also CPA-secure),
* and in this case they extend each other. Thus, it suffices to implement a Cca interface and this immediately implies that a Cpa interface is also implied.
* <p>
* All of the interfaces expressing a security level are marker interfaces that define types of security level and do not have any functionality.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*/
class SecurityNotion {};

/**
* This hierarchy specifies the security level of a cyclic group in which discrete log hardness is assumed to hold. The levels in this hierarchy are Dlog, CDH and DDH.
*/
class DiscretelogNotion : public SecurityNotion {};

/**
* A group in which the discrete log problem is assumed to hold should implement this interface.
*/
class Discretelog : public DiscretelogNotion {};

/**
* A group in which the computational Diffie-Hellman problem is assumed to hold should implement this interface.
*/
class CDH:public Discretelog {};

/**
* A group in which the decisional Diffie-Hellman problem is assumed to hold should implement this interface.
*/
class DDH : public CDH {};

/**
* This hierarchy specifies the security level of a cryptographic hash function. The levels in this hierarchy are TargetCollisionResistant and CollisionResistant.
*/
class HashSecurity : public SecurityNotion{};

/**
* This hierarchy specifies the security level of a message authentication code (MAC) or digital signature scheme.<p>
* The hierarchy here only refers to the number of times that the MAC or signature scheme can be used; namely, OneTime or UnlimitedTimes.
* We do not currently have another interface for a bounded but not unlimited number of times; if necessary this can be added later.
* We also consider by default adaptive chosen-message attacks and so have not defined a separate hierarchy for adaptive/non-adaptive attacks and chosen versus random message attacs.
*/
class MacSignSecurity : public SecurityNotion {};

/**
* Any MAC or signature scheme that is secure for one-time use only should implement this interface.
*/
class MacOneTime : public MacSignSecurity {};
/**
* Any MAC or signature scheme that is secure for an unlimited number of uses should implement this interface. This is the security level of standard MAC and signature schemes.
*/
class MacUnbounded : public MacOneTime {};
/**
* Any MAC or signature scheme that is secure for poly number of uses should implement this interface. This is the security level of standard MAC and signature schemes.
*/
class MacPolynomial : public MacOneTime {};

/**
* This hierarchy specifies the security level of encryption schemes; it does not differentiate between symmetric and asymmetric encryption.
* There are two sub-hierarchies for encryption. The first relates to the adversarial power and includes Eav (eavesdropping adversary), CPA (chosen-plaintext attack),
* CCA1 (preprocessing chosen-ciphertext attack), and CCA2 (full chosen-ciphertext attack). The second relates to the aim of the attack and includes Indistinguishable (for the standard indistinguishability notion) and NonMalleable;
* note that non-malleability implies indistinguishability and thus the NonMalleable interface extends the Indistinguishable interface.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class EncSecurity : public SecurityNotion {};

/**
* An encryption scheme that is only secure for eavesdropping adversaries (like a stream cipher) should implement this interface.
* It is also necessary to specify if such a scheme is Indistinguishable or NonMalleable.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class EavCoa : public EncSecurity {};

/**
* An encryption scheme that is secure in the presence of chosen-plaintext attacks should implement this interface.
* It is also necessary to specify if such a scheme is Indistinguishable or NonMalleable.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*/

class IndCpa : public EavCoa {};

/**
* An encryption scheme that is secure in the presence of preprocessing chosen-ciphertext attacks
* (meaning that the decryption oracle is available only before the challenge ciphertext is provided) should implement this interface.
* It is also necessary to specify if such a scheme is Indistinguishable or NonMalleable.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class IndCca1 : public IndCpa {};

/**
* This interface should be used when the security level of the encryption scheme is according to the regular indistinguishability game that defines privacy.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*/
class Indistinguishable : public EncSecurity {};

/**
* This interface should be used for encryption schemes that achieve non-malleability, meaning that it is infeasible for an adversary to generate a related ciphertext.
* Non-malleability always implies indistinguishability.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*/
class NonMalleable : public Indistinguishable {};

/**
* An encryption scheme that is secure in the presence of (full) chosen-ciphertext attacks should implement this interface.
* Note that any Cca2 scheme is both Indistinguishable and NonMalleable. Thus, Cca2 extends both Cca1 and NonMalleable,
* and it suffices to have a CCA2-secure scheme implement only the Cca2 interface.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*/
class IndCca2 : public IndCca1, NonMalleable {};

/**
* This interface is the root interface of the security level hierarchy for (secure computation) protocols.<p>
* There are three different subhierarchies in this family. The first relates to the adversary's capabilities and includes
* Semihonest, Malicious and Covert. The second relates to the question of composition and includes StandAlone and UC (universally composable).
* The third relates to the corruption strategy of the adversary and includes AdaptiveWithErasures and AdaptiveNoErasures
* (if no interface here is implemented then static security is assumed).
*/
class ProtocolSecurity : public SecurityNotion {};

class CommitSecurity : public SecurityNotion {};
class SecureCommit : public CommitSecurity {};
class StatisticallyHidingCmt : public SecureCommit {};
class EquivocalCmt : public SecureCommit {};
/**
* Any commitment scheme that is perfectly hiding should implement this interface.
*/
class PerfectlyHidingCmt : public StatisticallyHidingCmt {};

/**
* Any commitment scheme that is perfectly binding should implement this interface.
*/
class PerfectlyBindingCmt : public SecureCommit {}; 
/**
* Any protocol that is secure in the presence of semi-honest adversaries should implement this interface.
*/
class SemiHonest : public ProtocolSecurity {};

class PrivacyOnly : public ProtocolSecurity {};

/**
* Any protocol that is proven secure in the stand-alone model (where secure protocols are run sequentially and not concurrently) should implement this interface.
*/
class StandAlone : public ProtocolSecurity {};

/**
* Any protocol that is secure in the presence of covert adversaries should implement this interface.
* We stress that the deterrent parameter is not guaranteed by the interface.
*/
class Covert : public SemiHonest {};

class OneSidedSimulation : public ProtocolSecurity {};

/**
* Any protocol that is secure in the presence of malicious adversaries should implement this interface.
*
*/
class Malicious :public Covert, OneSidedSimulation {};

class UC :public StandAlone {};

