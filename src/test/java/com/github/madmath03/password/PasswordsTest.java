/*
 * Creation by l33tm the 2017-07-14.
 */

package com.github.madmath03.password;

import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Passwords utility class Test.
 * 
 * @author madmath03
 */
public class PasswordsTest {
  private static final String PASSWORD_PATTERN = "[a-zA-Z0-9]+";
  private static Pattern PATTERN;

  private Matcher patternMatcher;

  /**
   * Set the test case before loading the test class.
   * 
   * @throws java.lang.Exception if anything wrong happens during setup.
   */
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    PasswordsTest.PATTERN = Pattern.compile(PASSWORD_PATTERN);
  }

  /**
   * Tear down the test case setup after unloading the test class.
   * 
   * @throws java.lang.Exception if anything wrong happens during tear down.
   */
  @AfterClass
  public static void tearDownAfterClass() throws Exception {
    PasswordsTest.PATTERN = null;
  }

  /**
   * Set the test case before creating the test instance.
   * 
   * @throws java.lang.Exception if anything wrong happens during setup.
   */
  @Before
  public void setUp() throws Exception {}

  /**
   * Tear down the test case setup after leaving the test instance.
   * 
   * @throws java.lang.Exception if anything wrong happens during tear down.
   */
  @After
  public void tearDown() throws Exception {
    if (this.patternMatcher != null) {
      this.patternMatcher.reset();
      this.patternMatcher = null;
    }
  }

  /**
   * Test generation of a random salt to be used to hash a password.
   */
  @Test
  public void testGetNextSalt() {
    final byte[] salt = Passwords.getNextSalt();

    org.junit.Assert.assertTrue("Salt is not null", salt != null);

    org.junit.Assert.assertTrue("Salt is not empty", salt.length > 0);

    final byte[] salt2 = Passwords.getNextSalt();

    org.junit.Assert.assertFalse("Generated salt are always different",
        salt.equals(salt2));
  }

  /**
   * Test generation of a salted and hashed password using the provided hash.<br>
   * Test side effect: the password is destroyed (the char[] is filled with zeros).
   */
  @Test
  public void testGetHash() {
    final byte[] salt = Passwords.getNextSalt();
    final char[] password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    final char[] password2 = password.clone();
    final char[] destroyedPassword = new char[password.length];

    final String hash = Passwords.getHash(password, salt);

    org.junit.Assert.assertTrue("Hash password is not null", hash != null);

    org.junit.Assert.assertTrue("Hash password is not empty",
        hash.length() > 0);

    org.junit.Assert.assertTrue("Password size has not changed",
        password.length == destroyedPassword.length);

    for (final char c : password) {
      if (c != Character.MIN_VALUE) {
        org.junit.Assert.fail("Password has not been destroyed");
      }
    }

    final byte[] salt2 = Passwords.getNextSalt();
    final byte[] hash2 = Passwords.hash(password2, salt2);

    org.junit.Assert.assertFalse("Hashed passwords are always different",
        hash.equals(hash2));
  }

  /**
   * Test generation of a salted and hashed password using the provided hash.<br>
   * Test side effect: the password is destroyed (the char[] is filled with zeros).
   */
  @Test
  public void testHash() {
    final byte[] salt = Passwords.getNextSalt();
    final char[] password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    final char[] password2 = password.clone();
    final char[] password3 = password.clone();
    final char[] destroyedPassword = new char[password.length];

    final byte[] hash = Passwords.hash(password, salt);

    org.junit.Assert.assertTrue("Hash password is not null", hash != null);

    org.junit.Assert.assertTrue("Hash password is not empty", hash.length > 0);

    org.junit.Assert.assertTrue("Hash password has the proper size",
        hash.length == 64);

    org.junit.Assert.assertTrue("Password size has not changed",
        password.length == destroyedPassword.length);

    for (final char c : password) {
      if (c != Character.MIN_VALUE) {
        org.junit.Assert.fail("Password has not been destroyed");
      }
    }

    final byte[] salt2 = Passwords.getNextSalt();
    final byte[] hash2 = Passwords.hash(password2, salt2);

    org.junit.Assert.assertFalse("Hashed passwords are always different",
        hash.equals(hash2));

    try {

      final byte[] salt3 = Passwords.getNextSalt();
      Passwords.hash(password3, salt3, -1);
      org.junit.Assert.fail("Hash should fail");
    } catch (IllegalArgumentException e) {
      org.junit.Assert.assertTrue("Hashing failures handled", e != null);
    }
  }

  /**
   * Test if the given password and salt match the hashed value.<br>
   * Test side effect: the password is destroyed (the char[] is filled with zeros).
   */
  @Test
  public void testIsExpectedPasswordString() {
    final byte[] salt = Passwords.getNextSalt();
    final char[] password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    final char[] passwordCopy = password.clone();
    final char[] differentSizePassword = {'t', 'e', 's', 't'};
    final char[] differentValuePassword =
        {'d', 'r', 'o', 'w', 's', 's', 'a', 'p'};
    final char[] differentCasePassword =
        {'P', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    final char[] destroyedPassword = new char[password.length];

    final String hash = Passwords.getHash(password, salt);

    final boolean passwordMatches =
        Passwords.isExpectedPassword(passwordCopy, salt, hash);

    org.junit.Assert.assertTrue("Passwords match", passwordMatches);

    org.junit.Assert.assertTrue("Password size has not changed",
        password.length == destroyedPassword.length);

    for (final char c : password) {
      if (c != Character.MIN_VALUE) {
        org.junit.Assert.fail("Password has not been destroyed");
      }
    }

    final boolean passwordSizeNotMatches =
        Passwords.isExpectedPassword(differentSizePassword, salt, hash);

    org.junit.Assert.assertFalse("Passwords size do not match",
        passwordSizeNotMatches);

    final boolean passwordValuesNotMatches =
        Passwords.isExpectedPassword(differentValuePassword, salt, hash);

    org.junit.Assert.assertFalse("Passwords values do not match",
        passwordValuesNotMatches);

    final boolean passwordCaseNotMatches =
        Passwords.isExpectedPassword(differentCasePassword, salt, hash);

    org.junit.Assert.assertFalse("Passwords case do not match",
        passwordCaseNotMatches);

    try {
      Passwords.isExpectedPassword(differentValuePassword, salt, "");
      org.junit.Assert.fail("Passwords should fail");
    } catch (IllegalArgumentException e) {
      org.junit.Assert.assertTrue("Passwords format do not match", e != null);
    }

  }

  /**
   * Test if the given password and salt match the hashed value.<br>
   * Test side effect: the password is destroyed (the char[] is filled with zeros).
   */
  @Test
  public void testIsExpectedPasswordByte() {
    final byte[] salt = Passwords.getNextSalt();
    final char[] password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    final char[] passwordCopy = password.clone();
    final char[] differentSizePassword = {'t', 'e', 's', 't'};
    final char[] differentValuePassword =
        {'d', 'r', 'o', 'w', 's', 's', 'a', 'p'};
    final char[] differentCasePassword =
        {'P', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    final char[] destroyedPassword = new char[password.length];

    final byte[] hash = Passwords.hash(password, salt);

    final boolean passwordMatches =
        Passwords.isExpectedPassword(passwordCopy, salt, hash);

    org.junit.Assert.assertTrue("Passwords matches", passwordMatches);

    org.junit.Assert.assertTrue("Password size has not changed",
        password.length == destroyedPassword.length);

    for (final char c : password) {
      if (c != Character.MIN_VALUE) {
        org.junit.Assert.fail("Password has not been destroyed");
      }
    }

    final boolean passwordSizeNotMatches =
        Passwords.isExpectedPassword(differentSizePassword, salt, hash);

    org.junit.Assert.assertFalse("Passwords size do not match",
        passwordSizeNotMatches);

    final boolean passwordValuesNotMatches =
        Passwords.isExpectedPassword(differentValuePassword, salt, hash);

    org.junit.Assert.assertFalse("Passwords values do not match",
        passwordValuesNotMatches);

    final boolean passwordCaseNotMatches =
        Passwords.isExpectedPassword(differentCasePassword, salt, hash);

    org.junit.Assert.assertFalse("Passwords case do not match",
        passwordCaseNotMatches);

    final boolean passwordFormatNotMatches = Passwords
        .isExpectedPassword(differentValuePassword, salt, new byte[] {});

    org.junit.Assert.assertFalse("Passwords format do not match",
        passwordFormatNotMatches);

  }

  /**
   * Test generation of a random password of a given length, using letters and digits.
   */
  @Test
  public void testGenerateRandomPassword() {
    final int size = new Random().nextInt(63) + 1;
    final String randomPassword = Passwords.generateRandomPassword(size);

    org.junit.Assert.assertTrue("Random password is not null",
        randomPassword != null);

    org.junit.Assert.assertTrue("Random password is not empty",
        randomPassword.length() > 0);

    org.junit.Assert.assertTrue("Random password has the proper size",
        randomPassword.length() == size);

    this.patternMatcher = PATTERN.matcher(randomPassword);
    org.junit.Assert.assertTrue("Random password is human readable",
        this.patternMatcher.matches());
  }

}
