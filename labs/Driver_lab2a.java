/**
 * file: Driver_lab2a.java
 * author: Christopher Ravosa
 * course: MSCS 630L
 * assignment: lab 2
 * due date: January 30, 2022
 * version: 1.0
 *
 * This file contains the Driver_lab2a program which implements the Euclidean
 * algorithm to find the greatest common divisor of two integers.
 */

package src;

import java.util.Scanner;

/**
 * Driver_lab2a
 *
 * This class accepts two integers as user inputs and utilizes the euclidAlg()
 * method to find the greatest common divisor between them.
 */
public class Driver_lab2a {
  /**
   * main
   *
   * This function accepts two integers from the user and utilizes the
   * euclidAlg() method to find the greatest common divisor between them.
   *
   * Parameters:
   *   args: command line arguments
   *
   * Return value: none.
   */
  public static void main(String[] args) {
    long a;
    long b;
    long temp;

    // Ask user to input two integers.
    Scanner sc = new Scanner(System.in);
    System.out.print("Input integer A:");
    a = sc.nextLong();
    System.out.print("Input integer B:");
    b = sc.nextLong();
    sc.close();

    // If a < b, they should be swapped.
    if (a < b) {
      temp = a;
      a = b;
      b = temp;
    }

    // Print the greatest common divisor between the two integers.
    System.out.println(euclidAlg(a, b));
  }

  /**
   * euclidAlg
   *
   * This function receives a pair of positive integers, and returns the
   * corresponding greatest common divisor as an integer.
   *
   * Parameters:
   *   a: an integer greater than or equal to b
   *   b: an integer less than or equal to a
   *
   * Return value: a long representing the greatest common divisor.
   */
  public static long euclidAlg(long a, long b) {
    // The divisor return value used to prevent extraneous returns.
    long d;

    // If remainder is 0, b is the gcd of the original input values.
    if (a == 0)
      d = b;
    // Otherwise, apply the division algorithm.
    else
      d = euclidAlg(b % a, a);

    // Kick the divisor back up the ladder.
    return d;
  }
}
