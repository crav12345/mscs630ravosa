/**
 * file: AESCipher.java
 * author: Christopher Ravosa
 * course: MSCS 630L
 * assignment: lab 4
 * due date: February 20, 2022
 * version: 1.0
 *
 * This file contains the AESCipher program, an implementation of the Advanced
 * Encryption Standard (AES).
 */

package src;

/**
 * AESCipher
 *
 * This class contains methods for implementing the AES algorithm.
 */
public abstract class AESCipher {
    // Constant to store our substitution box matrix.
    static final int[][] S_BOX = {
            { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
              0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
            { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
              0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
            { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
              0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
            { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
              0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
            { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
              0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
            { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
              0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
            { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
              0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
            { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
              0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
            { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
              0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
            { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
              0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
            { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
              0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
            { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
              0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
            { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
              0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
            { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
              0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
            { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
              0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
            { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
              0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
    };

    // Constant to store our round constant lookup table.
    static final int[][] R_CON = {
            { 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
              0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A },
            { 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
              0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39 },
            { 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25,
              0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A },
            { 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08,
              0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8 },
            { 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6,
              0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF },
            { 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61,
              0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC },
            { 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01,
              0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B },
            { 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E,
              0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3 },
            { 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4,
              0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94 },
            { 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8,
              0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20 },
            { 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D,
              0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35 },
            { 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91,
              0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F },
            { 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D,
              0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04 },
            { 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C,
              0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63 },
            { 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA,
              0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD },
            { 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66,
              0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D }
    };

    static final int[][] GALOIS_FIELD_2 = {
            { 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
                    0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e },
            { 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e,
                    0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e },
            { 0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e,
                    0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e },
            { 0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e,
                    0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e },
            { 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
                    0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e },
            { 0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae,
                    0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe },
            { 0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce,
                    0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde },
            { 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
                    0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe },
            { 0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15,
                    0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05 },
            { 0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35,
                    0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25 },
            { 0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55,
                    0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45 },
            { 0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75,
                    0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65 },
            { 0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95,
                    0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85 },
            { 0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5,
                    0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5 },
            { 0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5,
                    0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5 },
            { 0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5,
                    0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5 }
    };

    static final int[][] GALOIS_FIELD_3 = {
            { 0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09,
                    0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11 },
            { 0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39,
                    0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21 },
            { 0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69,
                    0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71 },
            { 0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59,
                    0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41 },
            { 0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9,
                    0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1 },
            { 0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9,
                    0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1 },
            { 0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9,
                    0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1 },
            { 0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99,
                    0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81 },
            { 0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92,
                    0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a },
            { 0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2,
                    0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba },
            { 0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2,
                    0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea },
            { 0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2,
                    0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda },
            { 0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52,
                    0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c, 0x49, 0x4a },
            { 0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62,
                    0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a },
            { 0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32,
                    0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a },
            { 0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02,
                    0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a }
    };

    /**
     * aesRoundKeys
     *
     * This function produces 11 round keys from a hex representation of a
     * provided system key according to the key expansion aspect of the AES. In
     * order to do this, the method utilizes the helper methods, aesSBox() and
     * aesRCon().
     *
     * Parameters:
     *   keyHex: 16 hex character representation of a provided system key
     *
     * Return value: an array of strings representing the 11 round keys.
     */
    public static String[] aesRoundKeys(String keyHex) {
        // Used to return the round key strings.
        String[] roundKeys = {"","","","","","","","","","",""};

        // Array used to split the input key into pairs of hex digits for
        // storage in the 4x4 matrix representation of Ke.
        String[] keyHexPairs;

        // Convert keyHex into pairs of strings representing hex digits.
        keyHexPairs = keyHex.split("(?<=\\G..)");

        // Counter to keep track of which pair of hex integer is on deck.
        int pairsIndex = 0;

        // Stores the matrix representation of our system key.
        int[][] Ke = new int[4][4];

        // Fill the Ke matrix with the hex integers.
        for (int row = 0; row < Ke.length; row++) {
            for (int col = 0; col < Ke.length; col++) {
                Ke[row][col] = Integer.parseInt(keyHexPairs[pairsIndex], 16);
                pairsIndex++;
            }
        }

        // Stores 4x44 matrix containing representations of 11 round keys.
        int[][] W = new int[4][44];

        // Fill first four columns of W matrix with Ke values.
        for (int row = 0; row < Ke.length; row++) {
            System.arraycopy(Ke[row], 0, W[row], 0, Ke[0].length);
        }

        // Iterate through all remaining elements of the W matrix.
        for (int j = 4; j < W[0].length; j++) {
            // Check if the column index is not a multiple of four.
            if (j % 4 != 0) {
                // Perform an XOR operation on the 4th past and last column
                // with respect to the index of this column.
                W[0][j] = W[0][j - 4] ^ W[0][j - 1];
                W[1][j] = W[1][j - 4] ^ W[1][j - 1];
                W[2][j] = W[2][j - 4] ^ W[2][j - 1];
                W[3][j] = W[3][j - 4] ^ W[3][j - 1];
            }
            // Handle column indices which ARE a multiple of four.
            else {
                // Create column vector, wNew, with previous column.
                int[] wNew = {
                        W[0][j - 1],
                        W[1][j - 1],
                        W[2][j - 1],
                        W[3][j - 1]
                };

                // Store first element of wNew, so we can shift left.
                int temp = wNew[0];

                // Shift all elements of wNew to the left.
                for(int i = 0; i < wNew.length; i++) {
                    if (i == wNew.length - 1)
                        wNew[i] = temp;
                    else
                        wNew[i] = wNew[i+1];
                }

                // Transform each of the four bytes in wNew using aesSBox().
                for (int i = 0; i < wNew.length; i++) {
                    String hexString = String.format("%02X", wNew[i]);
                    wNew[i] = aesSBox(hexString);
                }

                // Get RCon(i) constant using the round constant search table.
                int rCon = aesRCon((int)Math.floor(j >> 2));

                // Perform XOR operation using rCon you just obtained.
                wNew[0] = rCon ^ wNew[0];

                // Finally, w(j) can be defined as w(j) = w(j-4) XOR wNew.
                W[0][j] = W[0][j - 4] ^ wNew[0];
                W[1][j] = W[1][j - 4] ^ wNew[1];
                W[2][j] = W[2][j - 4] ^ wNew[2];
                W[3][j] = W[3][j - 4] ^ wNew[3];
            }
        }

        // Load 4x4 chunks of W into strings in the roundKeys array.
        int currentRound = 0;
        for (int row = 0; row < W.length; row++) {
            for (int col = 0; col < W[0].length; col++) {
                if (col != 0 && col % 4 == 0)
                    currentRound++;

                if ((col + 1) % 4 == 0 && row == W.length - 1)
                    roundKeys[currentRound] +=
                            String.format("%02X", W[row][col]);
                else
                    roundKeys[currentRound] +=
                            String.format("%02X", W[row][col]) + ", ";
            }
            currentRound = 0;
        }
        return roundKeys;
    }

    /**
     * aesSBox
     *
     * This function finds the proper substitution for a hexadecimal integer in
     * a column vector by utilizing the AES substitution box.
     *
     * Parameters:
     *   inHex: a string representing a pair of hexadecimal digits
     *
     * Return value: an integer representing a hexadecimal substitution value.
     */
    static int aesSBox(String inHex) {
        int substitution;

        char row = inHex.charAt(0);
        char col = inHex.charAt(1);

        int rowNum = Integer.parseInt(Character.toString(row),16);
        int colNum = Integer.parseInt(Character.toString(col),16);

        substitution = S_BOX[rowNum][colNum];

        return substitution;
    }

    /**
     * aesRCon
     *
     * This function utilizes the R_CON lookup table to find the round constant
     * given a round number for AES key scheduling.
     *
     * Parameters:
     *   round: an integer >= 0
     *
     * Return value: an integer representing a hexadecimal round constant.
     */
    static int aesRCon(int round) {
        return R_CON[0][round];
    }

    /**
     * aesStateXOR
     *
     * This function performs the AES 'add round key' operation, producing an
     * output matrix which represents the XOR of the corresponding input
     * matrices.
     *
     * Parameters:
     *   sHex: a 4x4 matrix of hex digits
     *   keyHex: a 4x4 matrix of hex digits
     *
     * Return value: a 4x4 matrix representing the XOR of the input matrices.
     */
    static int[][] aesStateXOR(int[][] sHex, int[][] keyHex) {
        // Resulting XOR matrix which will be returned.
        int[][] outStateHex = new int[4][4];

        // Perform an XOR operation on each of the columns of the two input
        // matrices, storing the result in outStateHex.
        for (int i = 0; i < outStateHex.length; i++) {
            outStateHex[i][0] = sHex[i][0] ^ keyHex[i][0];
            outStateHex[i][1] = sHex[i][1] ^ keyHex[i][1];
            outStateHex[i][2] = sHex[i][2] ^ keyHex[i][2];
            outStateHex[i][3] = sHex[i][3] ^ keyHex[i][3];
        }

        return outStateHex;
    }

    /**
     * aesNibbleSub
     *
     * This method creates and returns a matrix whose values represent S-Box
     * substitutions performed on the input matrix's indices.
     *
     * Parameters:
     *   inStateHex: a 4x4 matrix of hex digits
     *
     * Return value: a 4x4 matrix of S-Box substitutions of the input matrix.
     */
    static int[][] aesNibbleSub(int[][] inStateHex) {
        // Resulting substitution matrix which will be returned.
        int[][] outStateHex = new int[4][4];

        // Perform S-Box substitutions on each index of inStateHex and store
        // the results in the outStateHex matrix.
        for (int i = 0; i < inStateHex.length; i++) {
            for (int j = 0; j < inStateHex[0].length; j++) {
                outStateHex[i][j] = aesSBox(
                        // Convert hex pairs to strings for aesSBox() to use.
                        String.format("%02x", inStateHex[i][j])
                );
            }
        }

        return outStateHex;
    }

    /**
     * aesShiftRow
     *
     * Performs a transformation on each row of an input matrix which shifts
     * the values in each row left an amount based on the row index.
     *
     * Parameters:
     *   inStateHex: a 4x4 matrix of hex digits
     *
     * Return value: a 4x4 matrix representing the transformed input matrix.
     */
    static int[][] aesShiftRow(int[][] inStateHex) {
        // Transform every row of inStateHex and store it in outStateHex.
        for (int i = 0; i < inStateHex.length; i++) {
            // Shift the row as many times as needed.
            for (int transforms = 0; transforms < i; transforms++) {
                // Store leading element of inStateHex, so we can shift left.
                int temp = inStateHex[i][0];

                // Shift all elements left and store in outStateHex.
                for (int j = 0; j < inStateHex[i].length; j++) {
                    if (j == inStateHex[i].length - 1)
                        inStateHex[i][j] = temp;
                    else
                        inStateHex[i][j] = inStateHex[i][j+1];
                }
            }
        }

        return inStateHex;
    }

    /**
     * aesMixColumn
     *
     * This method performs the 'mix column' operation of AES to transform the
     * input matrix to a further diffused matrix. This is done by performing
     * a number of multiplication operations in the Galois fields.
     *
     * Parameters:
     *   inStateHex: a 4x4 matrix of hex digits
     *
     * Return value: a 4x4 matrix representing the AES mixed input matrix.
     */
    static int[][] aesMixColumn(int[][] s) {
        int[][] sPrime = new int[4][4];

        // Perform multiplications over Galois fields to compute mix on
        // each column in s.
        for (int j = 0; j < s.length; j++) {
            // Formula for row 1.
            sPrime[0][j] = gF2(String.format("%02x", s[0][j]))
                            ^ gF3(String.format("%02x", s[1][j]))
                            ^ s[2][j]
                            ^ s[3][j];

            // Formula for row 2.
            sPrime[1][j] = s[0][j]
                    ^ gF2(String.format("%02x", s[1][j]))
                    ^ gF3(String.format("%02x", s[2][j]))
                    ^ s[3][j];

            // Formula for row 3.
            sPrime[2][j] = s[0][j]
                    ^ s[1][j]
                    ^ gF2(String.format("%02x", s[2][j]))
                    ^ gF3(String.format("%02x", s[3][j]));

            // Formula for row 4.
            sPrime[3][j] = gF3(String.format("%02x", s[0][j]))
                    ^ s[1][j]
                    ^ s[2][j]
                    ^ gF2(String.format("%02x", s[3][j]));
        }

        return sPrime;
    }

    /**
     * gF2
     *
     * Performs a lookup to multiply a hex value by 2 over a Galois field to
     * complete the 'mix columns' step of AES.
     *
     * @param inHex
     * @return a Galois field substitution for a hex value multiplied by 2.
     */
    static int gF2(String inHex) {
        int substitution;

        char row = inHex.charAt(0);
        char col = inHex.charAt(1);

        int rowNum = Integer.parseInt(Character.toString(row),16);
        int colNum = Integer.parseInt(Character.toString(col),16);

        substitution = GALOIS_FIELD_2[rowNum][colNum];

        return substitution;
    }

    /**
     * gF3
     *
     * Performs a lookup to multiply a hex value by 3 over a Galois field to
     * complete the 'mix columns' step of AES.
     *
     * @param inHex
     * @return a Galois field substitution for a hex value multiplied by 3.
     */
    static int gF3(String inHex) {
        int substitution;

        char row = inHex.charAt(0);
        char col = inHex.charAt(1);

        int rowNum = Integer.parseInt(Character.toString(row),16);
        int colNum = Integer.parseInt(Character.toString(col),16);

        substitution = GALOIS_FIELD_3[rowNum][colNum];

        return substitution;
    }

    /**
     * aes
     *
     * Executes a whole AES implementation.
     *
     * @param pTextHex
     * @param keyHex
     * @return
     */
    static String aes(String pTextHex, String keyHex) {
        // Stores the ciphertext which will be returned.
        StringBuilder cTextHex = new StringBuilder();

        // Stores the state matrix as it is created.
        int[][] outStateHex = new int[4][4];

        // Stores all of our round keys.
        String[] roundKeysHex;

        // These allow us to convert and add hex digits to a matrix.
        String newHex;
        int charLocation = 0;

        // Matrix to store and add keys after they've been generated.
        int[][] keyHexMatrix = new int[4][4];

        // Matrix to store encryption.
        int[][] sHex = new int[4][4];

        // Generate the keys for each round of encryption.
        roundKeysHex = aesRoundKeys(keyHex);

        // Convert the plaintext into a 4x4 matrix.
        for (int i = 0; i < sHex.length; i++) {
            for (int j = 0; j < sHex[0].length; j++) {
                newHex =
                        Character.toString(
                                pTextHex.charAt(charLocation)
                        ) +
                                pTextHex.charAt(charLocation + 1);

                charLocation += 2;

                sHex[i][j] = Integer.parseInt(newHex, 16);
            }
        }

        for (int roundNum = 0; roundNum < roundKeysHex.length; roundNum++) {
            // Reset the location index.
            charLocation = 0;

            // Convert the round key into a 4x4 matrix.
            for (int i = 0; i < keyHexMatrix.length; i++) {
                for (int j = 0; j < keyHexMatrix[0].length; j++) {
                    newHex =
                            Character.toString(
                                    roundKeysHex[roundNum]
                                            .charAt(charLocation)
                            ) +
                                    roundKeysHex[roundNum]
                                            .charAt(charLocation + 1);

                    charLocation += 4;

                    keyHexMatrix[i][j] = Integer.parseInt(newHex, 16);
                }
            }

            // Perform encryption round.
            if (roundNum == roundKeysHex.length - 1) {
                outStateHex =
                        aesShiftRow(
                                aesNibbleSub(
                                        aesStateXOR(
                                                sHex, keyHexMatrix
                                        )
                                )
                        );
            }
            else {
                outStateHex =
                        aesMixColumn(
                                aesShiftRow(
                                        aesNibbleSub(
                                                aesStateXOR(
                                                        sHex, keyHexMatrix
                                                )
                                        )
                                )
                        );
            }
        }

        // Convert result matrix to a cipher text string.
        for (int[] stateHex : outStateHex) {
            for (int hex : stateHex) {
                cTextHex.append(String.format("%02x", hex).toUpperCase());
            }
        }

        // Return the cipher text.
        return cTextHex.toString();
    }

    /**
     * printMatrix
     *
     * This function neatly prints any provided 2D matrix as a formatted string
     * of hex values. This was used for debugging purposes.
     *
     * Parameters:
     *   matrix: a 2D array of integers
     *
     * Return value: none.
     */
    static void printMatrix(int[][] matrix) {
        for (int[] ints : matrix) {
            System.out.print("[ ");
            for (int col = 0; col < matrix[0].length; col++) {
                if (col == matrix[0].length - 1) {
                    System.out.println(
                            String.format("%02X", ints[col])
                                    .toUpperCase() +
                                    " ]"
                    );
                } else {
                    System.out.print(
                            String.format("%02X", ints[col])
                                    .toUpperCase() +
                                    ", "
                    );
                }
            }
        }
        System.out.println();
    }

    /**
     * printVector
     *
     * This function neatly prints a provided column vector as a formatted
     * string. This was used for debugging purposes.
     *
     * Parameters:
     *   vector: an array of integers
     *
     * Return value: none.
     */
    static void printVector(int[] vector) {
        System.out.print("[ ");
        for (int i = 0; i < vector.length; i++) {
            System.out.print(String.format("%02X", vector[i]).toUpperCase());
            if (i != vector.length - 1) {
                System.out.print(", ");
            }
        }
        System.out.println(" ]");
    }
}