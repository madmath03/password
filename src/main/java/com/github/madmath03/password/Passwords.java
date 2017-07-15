package com.github.madmath03.password;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * A utility class to hash passwords and check passwords VS hashed values.
 * 
 * <p>
 * It uses a combination of hashing and unique salt. The algorithm used is
 * <strong>PBKDF2WithHmacSHA512</strong> which, although not the best for hashing password (vs.
 * <em>bcrypt</em>) is still considered robust and
 * <a href="https://security.stackexchange.com/a/6415/12614"> recommended by NIST</a>. The hashed
 * value has {@value #KEY_LENGTH} bits.
 * </p>
 * 
 * @see <a href="https://stackoverflow.com/a/18143616">How do I generate a SALT in Java for
 *      Salted-Hash?</a>
 * @see <a href="https://stackoverflow.com/questions/2860943/how-can-i-hash-a-password-in-java">How
 *      can I hash a password in Java?</a>
 * @see <a href=
 *      "https://security.stackexchange.com/questions/4781/do-any-security-experts-recommend-bcrypt-for-password-storage/6415#6415">Do
 *      any security experts recommend bcrypt for password storage?</a>
 * @see <a href="https://crackstation.net/hashing-security.htm">Salted Password Hashing - Doing it
 *      Right</a>
 */
public final class Passwords {

  /**
   * Each token produced by this class uses this identifier as a prefix.
   */
  private static final String HASH_ID = "$31$";

  /**
   * A Cryptographically Secure Pseudo-Random Number Generator to generate a Salt.
   */
  private static final Random RANDOM = new SecureRandom();
  /**
   * A standard algorithm to hash passwords.
   */
  private static final String ALGORITHM = "PBKDF2WithHmacSHA512";

  private static final int ITERATIONS = 10000;
  private static final int KEY_LENGTH = 512;
  private static final int SALT_SIZE = KEY_LENGTH / 8;

  /**
   * Hashed passwords pattern when displayed as {@code String}.
   */
  private static final Pattern PATTERN =
      Pattern.compile("\\$31\\$(\\d+)\\$(.*)");

  /**
   * Static utility class.
   */
  private Passwords() {}

  /**
   * Returns a random salt to be used to hash a password.
   *
   * @return a {@value #SALT_SIZE} bytes random salt
   */
  public static byte[] getNextSalt() {
    final byte[] salt = new byte[SALT_SIZE];
    RANDOM.nextBytes(salt);
    return salt;
  }

  /**
   * Returns a salted and hashed password using the provided hash.<br>
   * Note - side effect: the password is destroyed (the char[] is filled with zeros).
   *
   * @param password the password to be hashed.
   * @param salt a {@value #SALT_SIZE} bytes salt, ideally obtained with the getNextSalt method.
   *
   * @return the hashed password with a pinch of salt as a String.
   */
  public static String getHash(final char[] password, final byte[] salt) {
    return getHash(password, salt, ITERATIONS);
  }

  /**
   * Returns a salted and hashed password using the provided hash.<br>
   * Note - side effect: the password is destroyed (the char[] is filled with zeros).
   *
   * @param password the password to be hashed.
   * @param salt a {@value #SALT_SIZE} bytes salt, ideally obtained with the getNextSalt method.
   * @param iterations the iteration count.
   *
   * @return the hashed password with a pinch of salt as a String.
   */
  public static String getHash(final char[] password, final byte[] salt,
      final int iterations) {
    final byte[] hash = hash(password, salt, iterations);
    final Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
    return HASH_ID + iterations + '$' + enc.encodeToString(hash);
  }

  /**
   * Returns a salted and hashed password using the provided hash.<br>
   * Note - side effect: the password is destroyed (the char[] is filled with zeros).
   *
   * @param password the password to be hashed.
   * @param salt a {@value #SALT_SIZE} bytes salt, ideally obtained with the getNextSalt method.
   *
   * @return the hashed password with a pinch of salt.
   */
  public static byte[] hash(final char[] password, final byte[] salt) {
    return hash(password, salt, ITERATIONS);
  }

  /**
   * Returns a salted and hashed password using the provided hash.<br>
   * Note - side effect: the password is destroyed (the char[] is filled with zeros).
   *
   * @param password the password to be hashed.
   * @param salt a {@value #SALT_SIZE} bytes salt, ideally obtained with the getNextSalt method.
   * @param iterations the iteration count.
   *
   * @return the hashed password with a pinch of salt.
   */
  public static byte[] hash(final char[] password, final byte[] salt,
      final int iterations) {
    final PBEKeySpec spec =
        new PBEKeySpec(password, salt, iterations, KEY_LENGTH);

    // Destroy the password
    Arrays.fill(password, Character.MIN_VALUE);

    try {
      final SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
      return skf.generateSecret(spec).getEncoded();
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new AssertionError(
          "Error while hashing a password: " + e.getMessage(), e);
    } finally {
      spec.clearPassword();
    }
  }

  /**
   * Returns {@code true} if the given password and salt match the hashed value, {@code false}
   * otherwise.<br>
   * Note - side effect: the password is destroyed (the char[] is filled with zeros).
   *
   * @param password the password to check.
   * @param salt the salt used to hash the password.
   * @param expectedHash the expected hashed value of the password
   *
   * @return {@code true} if the given password and salt match the hashed value, {@code false}
   *         otherwise.
   */
  public static boolean isExpectedPassword(final char[] password,
      final byte[] salt, final String expectedHash) {
    final Matcher m = PATTERN.matcher(expectedHash);
    if (!m.matches()) {
      throw new IllegalArgumentException("Invalid hash format");
    }

    final int iterations = Integer.parseInt(m.group(1));
    final byte[] hash = Base64.getUrlDecoder().decode(m.group(2));

    return isExpectedPassword(password, salt, iterations, hash);
  }

  /**
   * Returns {@code true} if the given password and salt match the hashed value, {@code false}
   * otherwise.<br>
   * Note - side effect: the password is destroyed (the char[] is filled with zeros)
   *
   * @param password the password to check
   * @param salt the salt used to hash the password
   * @param expectedHash the expected hashed value of the password
   *
   * @return {@code true} if the given password and salt match the hashed value, {@code false}
   *         otherwise.
   */
  public static boolean isExpectedPassword(final char[] password,
      final byte[] salt, final byte[] expectedHash) {
    return isExpectedPassword(password, salt, ITERATIONS, expectedHash);
  }

  /**
   * Returns {@code true} if the given password and salt match the hashed value, {@code false}
   * otherwise.<br>
   * Note - side effect: the password is destroyed (the char[] is filled with zeros).
   *
   * @param password the password to check.
   * @param salt the salt used to hash the password.
   * @param iterations the iteration count for the hash.
   * @param expectedHash the expected hashed value of the password
   *
   * @return {@code true} if the given password and salt match the hashed value, {@code false}
   *         otherwise.
   */
  public static boolean isExpectedPassword(final char[] password,
      final byte[] salt, final int iterations, final byte[] expectedHash) {
    boolean passwordsMatch = true;

    final byte[] pwdHash = hash(password, salt, iterations);

    // Destroy the password
    Arrays.fill(password, Character.MIN_VALUE);

    if (pwdHash.length != expectedHash.length) {
      passwordsMatch = false;
    } else {

      for (int i = 0; i < pwdHash.length; i++) {
        if (pwdHash[i] != expectedHash[i]) {
          passwordsMatch = false;
          break;
        }
      }

    }

    return passwordsMatch;
  }

  /**
   * Generates a random password of a given length, using letters and digits.
   *
   * @param length the length of the password.
   *
   * @return a random password.
   */
  public static String generateRandomPassword(final int length) {
    final StringBuilder password = new StringBuilder(length);

    for (int i = 0; i < length; i++) {
      final int character = RANDOM.nextInt(62);
      if (character <= 9) {
        password.append(String.valueOf(character));
      } else if (character < 36) {
        password.append((char) ('a' + character - 10));
      } else {
        password.append((char) ('A' + character - 36));
      }
    }

    return password.toString();
  }
}
