package com.github.madmath03.password;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
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
 * <a href="https://security.stackexchange.com/a/6415/12614">recommended by NIST</a>. The hashed
 * value has {@value #KEY_LENGTH} bits.
 * </p>
 * 
 * @see <a href="https://stackoverflow.com/a/18143616">How do I generate a SALT in Java for
 *      Salted-Hash?</a>
 * @see <a href="https://stackoverflow.com/a/2861125">How can I hash a password in Java?</a>
 * @see <a href= "https://security.stackexchange.com/a/6415">Do any security experts recommend
 *      bcrypt for password storage?</a>
 * @see <a href="https://crackstation.net/hashing-security.htm">Salted Password Hashing - Doing it
 *      Right</a>
 */
public final class Passwords {

  private static final String ID = "31";

  /**
   * Each token produced by this class uses this identifier as a prefix.
   */
  private static final String HASH_ID = "$" + ID + "$";

  /**
   * A standard algorithm to hash passwords.
   */
  private static final String ALGORITHM = "PBKDF2WithHmacSHA512";
  /**
   * The algorithm key length.
   */
  private static final int KEY_LENGTH = 512;
  /**
   * The salt size.
   */
  public static final int SALT_SIZE = KEY_LENGTH / 8;

  /**
   * The minimum recommended cost, used by default.
   */
  public static final int DEFAULT_COST = 16;
  /**
   * The maximum cost.
   * 
   * <p>
   * Going higher would generate an overflow (going higher than {@code Integer.MAX_VALUE}) when
   * computing iterations.
   * </p>
   */
  public static final int MAXIMUM_COST = Integer.SIZE - 2;

  /**
   * Hashed passwords pattern when displayed as {@code String}.
   */
  private static final Pattern PATTERN =
      Pattern.compile("\\$" + ID + "\\$(\\d+)\\$(.{171})");

  /**
   * A pool of passwords manager based on their computational cost.
   */
  private static final Map<Integer, Passwords> POOL = new TreeMap<>();



  /**
   * A Cryptographically Secure Pseudo-Random Number Generator to generate a Salt.
   */
  private final Random random = new SecureRandom();
  /**
   * A Base64 encoder for encoding the hashed passwords and salt to strings.
   */
  private final Base64.Encoder encoder =
      Base64.getUrlEncoder().withoutPadding();
  /**
   * A Base64 decoder for decoding the hashed passwords and salt to strings.
   */
  private final Base64.Decoder decoder = Base64.getUrlDecoder();

  /**
   * The exponential computational cost of hashing a password.
   */
  private final int cost;

  /**
   * The iteration count for the password-based encryption (PBE).
   * 
   * @see #computeIterations(int)
   */
  private final int iterations;

  /**
   * Create a {@link Passwords} generator.
   * 
   * @param cost the exponential computational cost of hashing a password, 0 to
   *        {@value #MAXIMUM_COST}.
   * 
   * @throws IllegalArgumentException if the cost is not a multiple of 2 within 0 to
   *         {@value #MAXIMUM_COST}.
   */
  private Passwords(final int cost) {
    // Validate cost
    this.iterations = computeIterations(cost);
    this.cost = cost;
  }



  /**
   * Get a password manager to hash passwords and check passwords VS hashed values.
   * 
   * @return a password manager.
   * 
   * @throws IllegalArgumentException if the cost is not a multiple of 2 within 0 to
   *         {@value #MAXIMUM_COST}.
   */
  public static Passwords getManager() {
    return getManager(DEFAULT_COST);
  }

  /**
   * Get a password manager to hash passwords and check passwords VS hashed values.
   * 
   * <p>
   * The passwords manager are pooled by their computational costs, thus preventing allocation of
   * needless instances.
   * </p>
   * 
   * @param cost the exponential computational cost of hashing a password, 0 to
   *        {@value #MAXIMUM_COST}.
   * 
   * @return a password manager.
   * 
   * @throws IllegalArgumentException if the cost is not a multiple of 2 within 0 to
   *         {@value #MAXIMUM_COST}.
   */
  public static Passwords getManager(final int cost) {
    Passwords manager = POOL.get(cost);

    if (manager == null) {
      manager = new Passwords(cost);
      POOL.put(cost, manager);
    }

    return manager;
  }



  /**
   * Compute the number of iterations based on a cost.
   * 
   * @param cost the exponential computational cost of hashing a password, 0 to
   *        {@value #MAXIMUM_COST}.
   * 
   * @return the number of iterations based on the given cost.
   * 
   * @throws IllegalArgumentException if the cost is not a multiple of 2 within 0 to
   *         {@value #MAXIMUM_COST}.
   */
  private static int computeIterations(final int cost) {
    if ((cost & ~MAXIMUM_COST) != 0) {
      throw new IllegalArgumentException("Invalid cost: " + cost);
    }
    return 1 << cost;
  }



  /**
   * Returns a random salt to be used to hash a password.
   *
   * @return a {@value #SALT_SIZE} bytes random salt.
   */
  public static byte[] getSalt() {
    return Passwords.getManager().getNextSalt();
  }

  /**
   * Returns a random salt to be used to hash a password.
   *
   * @return a {@value #SALT_SIZE} bytes random salt.
   */
  public byte[] getNextSalt() {
    final byte[] salt = new byte[SALT_SIZE];
    random.nextBytes(salt);
    return salt;
  }



  /**
   * Generates a random password of a given length, using letters and digits.
   *
   * @return a random password.
   */
  public static String generateRandomPassword() {
    final Passwords passwords = Passwords.getManager();

    return passwords.generateRandomPassword(DEFAULT_COST);
  }

  /**
   * Generates a random password of a given length, using letters and digits.
   *
   * @param length the length of the password.
   *
   * @return a random password.
   */
  public String generateRandomPassword(final int length) {
    final StringBuilder password = new StringBuilder(length);

    for (int i = 0; i < length; i++) {
      final int character = random.nextInt(62);
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



  /**
   * Returns a salted and hashed password using the provided hash.
   * 
   * <p>
   * The result string follows the default hash {@link #PATTERN}.
   * </p>
   * 
   * <p>
   * Note - side effect: the password is destroyed (the {@code char[]} is filled with zeros).
   * </p>
   *
   * @param password the password to be hashed.
   *
   * @return the hashed password with a pinch of salt as a String.
   */
  public static String getHash(final char... password) {
    final Passwords passwords = Passwords.getManager();

    final byte[] salt = passwords.getNextSalt();

    return passwords.getHash(password, salt);
  }

  /**
   * Returns a salted and hashed password using the provided hash.
   * 
   * <p>
   * The result string follows the default hash {@link #PATTERN}.
   * </p>
   * 
   * <p>
   * Note - side effect: the password is destroyed (the {@code char[]} is filled with zeros).
   * </p>
   *
   * @param password the password to be hashed.
   * @param salt a {@value #SALT_SIZE} bytes salt, ideally obtained with the {@link #getNextSalt()}
   *        method.
   *
   * @return the hashed password with a pinch of salt as a String.
   */
  public String getHash(final char[] password, final byte[] salt) {
    final byte[] hash = this.hash(password, salt);

    final byte[] hashWithSalt = new byte[salt.length + hash.length];
    System.arraycopy(salt, 0, hashWithSalt, 0, salt.length);
    System.arraycopy(hash, 0, hashWithSalt, salt.length, hash.length);

    return HASH_ID + cost + '$' + encoder.encodeToString(hashWithSalt);
  }



  /**
   * Returns a salted and hashed password using the provided hash.
   * 
   * <p>
   * The resulting array starts contains the salt on the {@value #SALT_SIZE} first bytes, then the
   * hashed password itself.
   * </p>
   * 
   * <p>
   * Note - side effect: the password is destroyed (the {@code char[]} is filled with zeros).
   * </p>
   *
   * @param password the password to be hashed.
   *
   * @return the hashed password with a pinch of salt.
   */
  public static byte[] hash(final char... password) {
    final Passwords passwords = Passwords.getManager();

    final byte[] salt = passwords.getNextSalt();
    final byte[] hash = passwords.hash(password, salt);

    final byte[] hashWithSalt = new byte[salt.length + hash.length];
    System.arraycopy(salt, 0, hashWithSalt, 0, salt.length);
    System.arraycopy(hash, 0, hashWithSalt, salt.length, hash.length);

    return hashWithSalt;
  }

  /**
   * Returns a salted and hashed password using the provided hash.
   * 
   * <p>
   * Note - side effect: the password is destroyed (the {@code char[]} is filled with zeros).
   * </p>
   *
   * @param password the password to be hashed.
   * @param salt a {@value #SALT_SIZE} bytes salt, ideally obtained with the {@link #getNextSalt()}
   *        method.
   *
   * @return the hashed password with a pinch of salt.
   */
  public byte[] hash(final char[] password, final byte[] salt) {
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
   * otherwise.
   * 
   * <p>
   * Note - side effect: the password is destroyed (the {@code char[]} is filled with zeros).
   * </p>
   *
   * @param password the password to check.
   * @param expectedHash the expected hashed value of the password
   *
   * @return {@code true} if the given password and salt match the hashed value, {@code false}
   *         otherwise.
   */
  public static boolean isExpectedPassword(final char[] password,
      final String expectedHash) {
    if (expectedHash == null) {
      throw new IllegalArgumentException("Invalid hash");
    }

    final Matcher m = PATTERN.matcher(expectedHash);
    if (!m.matches()) {
      throw new IllegalArgumentException("Invalid hash format");
    }

    final int cost = Integer.parseInt(m.group(1));

    final Passwords passwords = Passwords.getManager(cost);
    final byte[] hashWithSalt = passwords.decoder.decode(m.group(2));
    final byte[] salt = Arrays.copyOfRange(hashWithSalt, 0, SALT_SIZE);
    final byte[] hash =
        Arrays.copyOfRange(hashWithSalt, SALT_SIZE, hashWithSalt.length);

    return passwords.isExpectedPassword(password, salt, hash);
  }

  /**
   * Returns {@code true} if the given password and salt match the hashed value, {@code false}
   * otherwise.
   * 
   * <p>
   * Note - side effect: the password is destroyed (the {@code char[]} is filled with zeros).
   * </p>
   *
   * @param password the password to check.
   * @param salt the salt used to hash the password.
   * @param expectedHash the expected hashed value of the password
   *
   * @return {@code true} if the given password and salt match the hashed value, {@code false}
   *         otherwise.
   */
  public boolean isExpectedPassword(final char[] password, final byte[] salt,
      final byte[] expectedHash) {
    if (expectedHash == null) {
      throw new IllegalArgumentException("Invalid hash");
    }

    boolean passwordsMatch = true;

    final byte[] pwdHash = this.hash(password, salt);

    // Destroy the password
    Arrays.fill(password, Character.MIN_VALUE);

    if (pwdHash.length == expectedHash.length) {

      for (int i = 0; i < pwdHash.length; i++) {
        if (pwdHash[i] != expectedHash[i]) {
          passwordsMatch = false;
          break;
        }
      }

    } else {
      passwordsMatch = false;
    }

    return passwordsMatch;
  }
}
