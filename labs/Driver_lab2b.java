/**
 * file: Driver_lab2b.java
 * author: Christopher Ravosa
 * course: MSCS 630L
 * assignment: lab 2
 * due date: January 30, 2022
 * version: 1.0
 *
 * This file contains the Driver_lab2b program which implements the Extended
 * Euclidean algorithm to find the greatest common divisor of two integers.
 */

package src;

import java.util.Scanner;

/**
 * Driver_lab2b
 *
 * This class accepts two integers as user inputs and utilizes the euclidAlgExt()
 * method to find the greatest common divisor between them.
 */
public class Driver_lab2b {
  /**
   * main
   *
   * This function accepts two integers from the user and utilizes the
   * euclidAlgExt() method to find the greatest common divisor between them.
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

    // Print the values of d, x, and y.
    for (long value : euclidAlgExt(a, b)) {
      System.out.print(value + " ");
    }
  }

  /**
   * euclidAlgExt
   *
   * This function receives a pair of positive integers, and returns an array
   * containing the greatest common divisor between them along with two
   * values, x and y, that satisfy the equation d = ax + by.
   *
   * Parameters:
   *   a: an integer greater than or equal to b
   *   b: an integer less than or equal to a
   *
   * Return value: an array containing the greatest common divisor, x, and y.
   */
  public static long[] euclidAlgExt(long a, long b) {
    // The divisor return array used to prevent extraneous returns.
    long[] dxy = new long[3];
    long x,y;

    // If remainder is 0, b is the gcd of the original input values.
    if (a == 0) {
      dxy[0] = b;
      dxy[1] = 0;
      dxy[2] = 1;
    }
    // Otherwise, apply the division algorithm.
    else {
      dxy = euclidAlgExt(b % a, a);

      // Update the x and y values of the dxy array.
      x = dxy[2] - (b/a) * dxy[1];
      y = dxy[1];
      dxy[1] = x;
      dxy[2] = y;
    }

    // Kick the array back up the ladder.
    return dxy;
  }
}
