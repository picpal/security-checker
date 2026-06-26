package com.example;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/** 의도적 SAST 취약 패턴 픽스처 (Semgrep 탐지 검증용). */
public class Vuln {

  /** SQL Injection (CWE-89): 사용자 입력을 쿼리 문자열에 직접 연결. */
  public ResultSet lookup(Connection con, String userId) throws SQLException {
    Statement st = con.createStatement();
    String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
    return st.executeQuery(sql);
  }

  /** Command Injection (CWE-78): 사용자 입력을 셸 명령 문자열에 연결해 실행. */
  public Process run(String userInput) throws Exception {
    String cmd = "/bin/sh -c ls " + userInput;
    return Runtime.getRuntime().exec(cmd);
  }
}
