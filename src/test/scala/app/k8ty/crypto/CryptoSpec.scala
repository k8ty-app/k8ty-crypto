package app.k8ty.crypto

import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should
import scala.util.Random

class CryptoSpec extends AnyFlatSpec with should.Matchers with Crypto  {

  val fakePassword = "t0tallySweetPassWurdz"
  val message = "The lazy fox..."

  "Crypto" should "be able to generate and validate a PBKDF2 hash" in {
    val hash = pbkdf2Hash(fakePassword)
    assert(validatePbkdf2Hash(fakePassword, hash))
  }

  it should "be able to encrypt / decrypt AES messages" in {

    val fakeKey16 = Random.alphanumeric.take(16).mkString
    val fakeKey24 = Random.alphanumeric.take(24).mkString
    val fakeKey32 = Random.alphanumeric.take(32).mkString
    val fakeKey20 = Random.alphanumeric.take(20).mkString

    val aes16 = aesEncrypt(message, fakeKey16)
    val aes24 = aesEncrypt(message, fakeKey24)
    val aes32 = aesEncrypt(message, fakeKey32)
    val aes20 = aesEncrypt(message, fakeKey20)

    assert(aes16.isSuccess)
    assert(aes24.isSuccess)
    assert(aes32.isSuccess)
    assert(aes20.isFailure)

    assert(!aes16.get.equals(aes24.get))
    assert(!aes16.get.equals(aes32.get))
    assert(!aes24.get.equals(aes32.get))

    val daes16 = aesDecrypt(aes16.get, fakeKey16)
    val daes24 = aesDecrypt(aes24.get, fakeKey24)
    val daes32 = aesDecrypt(aes32.get, fakeKey32)

    assert(daes16.isSuccess)
    assert(daes24.isSuccess)
    assert(daes32.isSuccess)

    assert(daes16.get.equals(message))
    assert(daes24.get.equals(message))
    assert(daes32.get.equals(message))

  }

  it should "be able to sign and verify messages with HMAC SHA256/SHA512" in {

    val s256 = hmac256(message, fakePassword)
    val s512 = hmac512(message, fakePassword)

    assert(validateHmac256(message, fakePassword, s256))
    assert(validateHmac512(message, fakePassword, s512))
    assert(!validateHmac512(message, fakePassword, s256))
    assert(!validateHmac256(message, fakePassword, s512))

  }

  it should "be able to Base64 (url) encode/decode string messages" in {
    val encoded = base64Encode(message)
    assert(!encoded.equals(message))
    assert(base64Decode(encoded).equals(message))
  }

  it should "be able to generate an API public key that is only alphanumeric" in {

    val invalid: List[Char] = List("[", "\\", "]", "^", "_", "`", ":", ";", "<", "=", ">", "?", "@").map(_.toCharArray).map(_(0))
    assert {
      (1 to 1000).map(_ => generatePublicKey).map { s =>
        s.toList.map(c => !invalid.contains(c)).reduceLeft(_ && _)
      }.reduceLeft(_ && _)
    }
  }

}

