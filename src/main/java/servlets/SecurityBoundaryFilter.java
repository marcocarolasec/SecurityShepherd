package servlets;

import java.io.IOException;
import java.util.Map;
import java.util.regex.Pattern;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

/** Applies baseline input, CSRF, framing, and session-cookie controls to training endpoints. */
public class SecurityBoundaryFilter implements Filter {

  private static final Pattern ATTACK_INPUT =
      Pattern.compile(
          "(?i)(<|>|javascript:|script|\\$\\{|['\";]|--|\\bunion\\b|\\bselect\\b|\\bor\\b\\s+[0-9]|\\(\\||\\*\\))");

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {}

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    HttpServletResponse httpResponse = (HttpServletResponse) response;
    httpResponse.setHeader("X-Frame-Options", "DENY");
    httpResponse.setHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'");
    httpResponse.setHeader("X-Content-Type-Options", "nosniff");

    if (hasAttackInput(httpRequest.getParameterMap()) || isCrossSiteMutation(httpRequest)) {
      httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
      return;
    }

    chain.doFilter(httpRequest, secureCookieResponse(httpResponse));
  }

  private boolean hasAttackInput(Map<String, String[]> parameters) {
    for (String[] values : parameters.values()) {
      for (String value : values) {
        if (value != null && ATTACK_INPUT.matcher(value).find()) {
          return true;
        }
      }
    }
    return false;
  }

  private boolean isCrossSiteMutation(HttpServletRequest request) {
    String method = request.getMethod();
    if (!("POST".equals(method) || "PUT".equals(method) || "DELETE".equals(method))) {
      return false;
    }
    String origin = request.getHeader("Origin");
    String referer = request.getHeader("Referer");
    String expected = request.getScheme() + "://" + request.getServerName();
    return (origin != null && !origin.startsWith(expected))
        || (origin == null && referer != null && !referer.startsWith(expected));
  }

  private HttpServletResponse secureCookieResponse(HttpServletResponse response) {
    return new HttpServletResponseWrapper(response) {
      @Override
      public void addCookie(Cookie cookie) {
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        super.addCookie(cookie);
      }
    };
  }

  @Override
  public void destroy() {}
}
