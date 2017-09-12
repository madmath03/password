/*
 * Creation by madmath03 the 2017-07-14.
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
  private static Pattern pattern;

  private Matcher patternMatcher;

  private Passwords manager;

  /**
   * Set the test case before loading the test class.
   * 
   * @throws java.lang.Exception if anything wrong happens during setup.
   */
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    PasswordsTest.pattern = Pattern.compile(PASSWORD_PATTERN);
  }

  /**
   * Tear down the test case setup after unloading the test class.
   * 
   * @throws java.lang.Exception if anything wrong happens during tear down.
   */
  @AfterClass
  public static void tearDownAfterClass() throws Exception {
    PasswordsTest.pattern = null;
  }

  /**
   * Set the test case before creating the test instance.
   * 
   * @throws java.lang.Exception if anything wrong happens during setup.
   */
  @Before
  public void setUp() throws Exception {
    this.manager = Passwords.getManager();
  }

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
   * Test method for {@link com.github.madmath03.password.Passwords#getManager()}.
   */
  @Test
  public void testGetPasswords() {
    final Passwords manager = Passwords.getManager();

    org.junit.Assert.assertFalse("Passwords manager is not null",
        manager == null);
  }

  /**
   * Test method for {@link com.github.madmath03.password.Passwords#getManager(int)}.
   */
  @Test
  public void testGetPasswordsInt() {
    Passwords manager;

    // loop for multiples of 2 within 0 to 30
    for (int i = 0; i <= Passwords.MAXIMUM_COST; i += 2) {
      manager = Passwords.getManager(i);

      org.junit.Assert.assertFalse(
          "Passwords manager allows any cost multiple of 2 within 0 to 30",
          manager == null);
    }



    // loop for numbers NOT multiples of 2 within 0 to 30
    manager = null;
    for (int i = 1; i <= Passwords.MAXIMUM_COST; i += 2) {
      try {
        manager = Passwords.getManager(i);
        org.junit.Assert.fail(
            "Passwords manager should refuse cost which is not a multiple of 2");
      } catch (Exception e) {
        org.junit.Assert.assertTrue(
            "Passwords manager refuses cost which is not a multiple of 2",
            manager == null);
      }
    }



    // loop for negative numbers
    manager = null;
    for (int i = -1, n = Passwords.MAXIMUM_COST * -2; i >= n; i--) {
      try {
        manager = Passwords.getManager(i);
        org.junit.Assert.fail("Passwords manager should refuse negative costs");
      } catch (Exception e) {
        org.junit.Assert.assertTrue("Passwords manager refuses negative costs",
            manager == null);
      }
    }



    // loop for numbers higher than Passwords.MAXIMUM_COST
    manager = null;
    for (int i = Passwords.MAXIMUM_COST + 1, n =
        Passwords.MAXIMUM_COST * 2; i <= n; i++) {
      try {
        manager = Passwords.getManager(i);
        org.junit.Assert.fail(
            "Passwords manager should refuse costs higher or equals to 31");
      } catch (Exception e) {
        org.junit.Assert.assertTrue(
            "Passwords manager refuses costs higher or equals to 31",
            manager == null);
      }
    }
  }

  /**
   * Test method for {@link com.github.madmath03.password.Passwords#getSalt()}.
   * 
   * <p>
   * Test static generation of a random salt to be used to hash a password.
   * </p>
   */
  @Test
  public void testGetSalt() {
    final byte[] salt = Passwords.getSalt();

    org.junit.Assert.assertTrue("Salt is not null", salt != null);

    org.junit.Assert.assertTrue("Salt is not empty", salt.length > 0);

    final byte[] salt2 = Passwords.getSalt();

    org.junit.Assert.assertFalse("Generated salt are always different",
        salt.equals(salt2));
  }

  /**
   * Test method for {@link com.github.madmath03.password.Passwords#getNextSalt()}.
   * 
   * <p>
   * Test generation of a random salt to be used to hash a password.
   * </p>
   */
  @Test
  public void testGetNextSalt() {
    Passwords manager = Passwords.getManager();

    final byte[] salt = manager.getNextSalt();

    org.junit.Assert.assertTrue("Salt is not null", salt != null);

    org.junit.Assert.assertTrue("Salt is not empty", salt.length > 0);

    final byte[] salt2 = manager.getNextSalt();

    org.junit.Assert.assertFalse("Generated salt are always different",
        salt.equals(salt2));
  }



  /**
   * Test method for {@link com.github.madmath03.password.Passwords#generateRandomPassword()}.
   * 
   * <p>
   * Test generation of a random password of a given length, using letters and digits.
   * </p>
   */
  @Test
  public void testGenerateRandomPassword() {
    final char[] randomPassword = Passwords.generateRandomPassword();

    org.junit.Assert.assertNotNull("Random password is not null",
        randomPassword);

    org.junit.Assert.assertTrue("Random password is not empty",
        randomPassword.length > 0);

    this.patternMatcher = pattern.matcher(new String(randomPassword));
    org.junit.Assert.assertTrue("Random password is human readable",
        this.patternMatcher.matches());
  }

  /**
   * Test method for {@link com.github.madmath03.password.Passwords#generateRandomPassword(int)}.
   * 
   * <p>
   * Test generation of a random password of a given length, using letters and digits.
   * </p>
   */
  @Test
  public void testGenerateRandomPasswordInt() {
    Passwords manager = Passwords.getManager();

    final int size = new Random().nextInt(63) + 1;
    final char[] randomPassword = manager.generateRandomPassword(size);

    org.junit.Assert.assertTrue("Random password is not null",
        randomPassword != null);

    org.junit.Assert.assertTrue("Random password is not empty",
        randomPassword.length > 0);

    org.junit.Assert.assertTrue("Random password has the proper size",
        randomPassword.length == size);

    this.patternMatcher = pattern.matcher(new String(randomPassword));
    org.junit.Assert.assertTrue("Random password is human readable",
        this.patternMatcher.matches());
  }



  /**
   * Test method for {@link com.github.madmath03.password.Passwords#getHash(char[])}.
   * 
   * <p>
   * Test generation of a salted and hashed password using the provided hash. Test side effect: the
   * password is destroyed (the {@code char[]} is filled with zeros).
   * </p>
   */
  @Test
  public void testGetHashCharArray() {
    final char[] password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    final char[] password2 = password.clone();
    final int passwordSize = password.length;

    final String hash = Passwords.getHash(password);

    org.junit.Assert.assertTrue("Hash password is not null", hash != null);

    org.junit.Assert.assertTrue("Hash password is not empty",
        hash.length() > 0);

    org.junit.Assert.assertTrue("Password size has not changed",
        password.length == passwordSize);

    for (final char c : password) {
      if (c != Character.MIN_VALUE) {
        org.junit.Assert.fail("Password has not been destroyed");
      }
    }

    final byte[] hash2 = Passwords.hash(password2);

    org.junit.Assert.assertFalse("Hashed passwords are always different",
        hash.equals(hash2));
  }

  /**
   * Test method for {@link com.github.madmath03.password.Passwords#getHash(char[], byte[])}.
   * 
   * <p>
   * Test generation of a salted and hashed password using the provided hash. Test side effect: the
   * password is destroyed (the {@code char[]} is filled with zeros).
   * </p>
   */
  @Test
  public void testGetHashCharArrayByteArray() {
    Passwords manager = Passwords.getManager();

    final byte[] salt = manager.getNextSalt();
    final char[] password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    final char[] password2 = password.clone();
    final int passwordSize = password.length;

    final String hash = manager.getHash(password, salt);

    org.junit.Assert.assertTrue("Hash password is not null", hash != null);

    org.junit.Assert.assertTrue("Hash password is not empty",
        hash.length() > 0);

    org.junit.Assert.assertTrue("Password size has not changed",
        password.length == passwordSize);

    for (final char c : password) {
      if (c != Character.MIN_VALUE) {
        org.junit.Assert.fail("Password has not been destroyed");
      }
    }

    final byte[] hash2 = manager.hash(password2, salt);

    org.junit.Assert.assertFalse("Hashed passwords are always different",
        hash.equals(hash2));
  }



  /**
   * Test method for {@link com.github.madmath03.password.Passwords#hash(char[])}.
   * 
   * <p>
   * Test generation of a salted and hashed password using the provided hash. Test side effect: the
   * password is destroyed (the {@code char[]} is filled with zeros).
   * </p>
   */
  @Test
  public void testHashCharArray() {
    final char[] password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    final char[] password2 = password.clone();
    final int passwordSize = password.length;

    final byte[] hash = Passwords.hash(password);

    org.junit.Assert.assertTrue("Hash password is not null", hash != null);

    org.junit.Assert.assertTrue("Hash password is not empty", hash.length > 0);

    org.junit.Assert.assertTrue("Password size has not changed",
        password.length == passwordSize);

    for (final char c : password) {
      if (c != Character.MIN_VALUE) {
        org.junit.Assert.fail("Password has not been destroyed");
      }
    }

    final byte[] hash2 = Passwords.hash(password2);

    org.junit.Assert.assertFalse("Hashed passwords are always different",
        hash.equals(hash2));
  }

  /**
   * Test method for {@link com.github.madmath03.password.Passwords#hash(char[], byte[])}.
   * 
   * <p>
   * Test generation of a salted and hashed password using the provided hash. Test side effect: the
   * password is destroyed (the {@code char[]} is filled with zeros).
   * </p>
   */
  @Test
  public void testHashCharArrayByteArray() {
    Passwords manager = Passwords.getManager();

    final byte[] salt = manager.getNextSalt();
    final char[] password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    final char[] password2 = password.clone();
    final int passwordSize = password.length;

    final byte[] hash = manager.hash(password, salt);

    org.junit.Assert.assertTrue("Hash password is not null", hash != null);

    org.junit.Assert.assertTrue("Hash password is not empty", hash.length > 0);

    org.junit.Assert.assertTrue("Hash password has the proper size",
        hash.length == 64);

    org.junit.Assert.assertTrue("Password size has not changed",
        password.length == passwordSize);

    for (final char c : password) {
      if (c != Character.MIN_VALUE) {
        org.junit.Assert.fail("Password has not been destroyed");
      }
    }

    final byte[] salt2 = manager.getNextSalt();
    final byte[] hash2 = manager.hash(password2, salt2);

    org.junit.Assert.assertFalse("Hashed passwords are always different",
        hash.equals(hash2));
  }



  /**
   * Test method for
   * {@link com.github.madmath03.password.Passwords#isExpectedPassword(CharSequence, String)}.
   * 
   * <p>
   * Test if the given password match the hashed value. Test side effect: the password is destroyed
   * (the {@code char[]} is filled with zeros).
   * </p>
   */
  @Test
  public void testIsExpectedPasswordCharSequenceString() {
    final String password = "password";
    final String passwordCopy = new String(password);
    final String differentSizePassword = "test";
    final String differentValuePassword = "drowssap";
    final String differentCasePassword = "Password";
    final int passwordSize = password.length();

    final String hash = Passwords.getHash(password.toCharArray().clone());

    final boolean passwordMatches =
        Passwords.isExpectedPassword(passwordCopy, hash);

    org.junit.Assert.assertTrue("Passwords match", passwordMatches);

    org.junit.Assert.assertTrue("Password size has not changed",
        password.length() == passwordSize);

    final boolean passwordSizeNotMatches =
        Passwords.isExpectedPassword(differentSizePassword, hash);

    org.junit.Assert.assertFalse("Passwords size do not match",
        passwordSizeNotMatches);

    final boolean passwordValuesNotMatches =
        Passwords.isExpectedPassword(differentValuePassword, hash);

    org.junit.Assert.assertFalse("Passwords values do not match",
        passwordValuesNotMatches);

    final boolean passwordCaseNotMatches =
        Passwords.isExpectedPassword(differentCasePassword, hash);

    org.junit.Assert.assertFalse("Passwords case do not match",
        passwordCaseNotMatches);

    try {
      Passwords.isExpectedPassword(password, "");
      org.junit.Assert.fail("Passwords format do not match");
    } catch (IllegalArgumentException e) {
      org.junit.Assert.assertTrue("Passwords format do not match", e != null);
    }

    try {
      Passwords.isExpectedPassword(password, null);
      org.junit.Assert.fail("Passwords hash that are null should fail");
    } catch (IllegalArgumentException e) {
      org.junit.Assert.assertTrue("Passwords hash null are not allowed",
          e != null);
    }

  }

  /**
   * Test method for
   * {@link com.github.madmath03.password.Passwords#isExpectedPassword(char[], java.lang.String)}.
   * 
   * <p>
   * Test if the given password match the hashed value. Test side effect: the password is destroyed
   * (the {@code char[]} is filled with zeros).
   * </p>
   */
  @Test
  public void testIsExpectedPasswordCharArrayString() {
    final char[] password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    final char[] passwordCopy = password.clone();
    final char[] differentSizePassword = {'t', 'e', 's', 't'};
    final char[] differentValuePassword =
        {'d', 'r', 'o', 'w', 's', 's', 'a', 'p'};
    final char[] differentCasePassword =
        {'P', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    final int passwordSize = password.length;

    final String hash = Passwords.getHash(password);

    final boolean passwordMatches =
        Passwords.isExpectedPassword(passwordCopy, hash);

    org.junit.Assert.assertTrue("Passwords match", passwordMatches);

    org.junit.Assert.assertTrue("Password size has not changed",
        password.length == passwordSize);

    for (final char c : password) {
      if (c != Character.MIN_VALUE) {
        org.junit.Assert.fail("Password has not been destroyed");
      }
    }

    final boolean passwordSizeNotMatches =
        Passwords.isExpectedPassword(differentSizePassword, hash);

    org.junit.Assert.assertFalse("Passwords size do not match",
        passwordSizeNotMatches);

    final boolean passwordValuesNotMatches =
        Passwords.isExpectedPassword(differentValuePassword, hash);

    org.junit.Assert.assertFalse("Passwords values do not match",
        passwordValuesNotMatches);

    final boolean passwordCaseNotMatches =
        Passwords.isExpectedPassword(differentCasePassword, hash);

    org.junit.Assert.assertFalse("Passwords case do not match",
        passwordCaseNotMatches);

    try {
      Passwords.isExpectedPassword(password, "");
      org.junit.Assert.fail("Passwords format do not match");
    } catch (IllegalArgumentException e) {
      org.junit.Assert.assertTrue("Passwords format do not match", e != null);
    }

    try {
      Passwords.isExpectedPassword(password, null);
      org.junit.Assert.fail("Passwords hash that are null should fail");
    } catch (IllegalArgumentException e) {
      org.junit.Assert.assertTrue("Passwords hash null are not allowed",
          e != null);
    }

    try {
      Passwords.isExpectedPassword((char[]) null, null);
      org.junit.Assert.fail("Passwords that are null should fail");
    } catch (IllegalArgumentException e) {
      org.junit.Assert.assertTrue("Passwords null are not allowed", e != null);
    }

  }

  /**
   * Test method for
   * {@link com.github.madmath03.password.Passwords#isExpectedPassword(char[], byte[], byte[])}.
   * 
   * <p>
   * Test if the given password and salt match the hashed value. Test side effect: the password is
   * destroyed (the {@code char[]} is filled with zeros).
   * </p>
   */
  @Test
  public void testIsExpectedPasswordCharArrayByteArrayByteArray() {
    final byte[] salt = manager.getNextSalt();
    final char[] password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    final char[] passwordCopy = password.clone();
    final char[] differentSizePassword = {'t', 'e', 's', 't'};
    final char[] differentValuePassword =
        {'d', 'r', 'o', 'w', 's', 's', 'a', 'p'};
    final char[] differentCasePassword =
        {'P', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    final int passwordSize = password.length;

    final byte[] hash = manager.hash(password, salt);

    final boolean passwordMatches =
        manager.isExpectedPassword(passwordCopy, salt, hash);

    org.junit.Assert.assertTrue("Passwords match", passwordMatches);

    org.junit.Assert.assertTrue("Password size has not changed",
        password.length == passwordSize);

    for (final char c : password) {
      if (c != Character.MIN_VALUE) {
        org.junit.Assert.fail("Password has not been destroyed");
      }
    }

    final boolean passwordSizeNotMatches =
        manager.isExpectedPassword(differentSizePassword, salt, hash);

    org.junit.Assert.assertFalse("Passwords size do not match",
        passwordSizeNotMatches);

    final boolean passwordValuesNotMatches =
        manager.isExpectedPassword(differentValuePassword, salt, hash);

    org.junit.Assert.assertFalse("Passwords values do not match",
        passwordValuesNotMatches);

    final boolean passwordCaseNotMatches =
        manager.isExpectedPassword(differentCasePassword, salt, hash);

    org.junit.Assert.assertFalse("Passwords case do not match",
        passwordCaseNotMatches);

    try {
      manager.isExpectedPassword(password, salt, null);
      org.junit.Assert.fail("Passwords hash that are null should fail");
    } catch (NullPointerException e) {
      org.junit.Assert.assertTrue("Passwords hash null are not allowed",
          e != null);
    }

    try {
      manager.isExpectedPassword(null, salt, null);
      org.junit.Assert.fail("Passwords hash that are null should fail");
    } catch (NullPointerException e) {
      org.junit.Assert.assertTrue("Passwords hash null are not allowed",
          e != null);
    }

    final boolean passwordHashSizeNotMatches =
        manager.isExpectedPassword(password, salt, new byte[] {});

    org.junit.Assert.assertFalse("Passwords hash size do not match",
        passwordHashSizeNotMatches);

  }

  @Test
  public void testConvertToCharArray() {
    final String rawPassword = "password";
    final char[] expectedPassword = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};

    final char[] password = Passwords.convertToCharArray(rawPassword);

    org.junit.Assert.assertNotNull(password);
    org.junit.Assert.assertArrayEquals(expectedPassword, password);
  }

}
