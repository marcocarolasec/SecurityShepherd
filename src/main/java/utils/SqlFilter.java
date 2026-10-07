package utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Filters used to make SQL injection more difficult to perform <br>
 * <br>
 * This file is part of the Security Shepherd Project.
 *
 * <p>The Security Shepherd project is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.<br>
 *
 * <p>The Security Shepherd project is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.<br>
 *
 * <p>You should have received a copy of the GNU General Public License along with the Security
 * Shepherd project. If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Mark Denihan
 */
public class SqlFilter {

  private static final Logger log = LogManager.getLogger(SqlFilter.class);

  public static String levelFour(String input) {
    return safeValue(input);
  }

  public static String levelOne(String input) {
    log.debug("Filtering input at SQL levelOne");
    return safeValue(input);
  }

  public static String levelThree(String input) {
    return safeValue(input);
  }

  public static String levelTwo(String input) {
    return safeValue(input);
  }

  private static String safeValue(String input) {
    if (input == null) {
      return "";
    }
    return input.replaceAll("[^A-Za-z0-9_@. ]", "");
  }
}
