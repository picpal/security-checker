package com.example;

import org.apache.commons.text.StringSubstitutor;

/**
 * 의도적 취약 픽스처.
 *
 * <p>commons-text 의 StringSubstitutor 보간을 신뢰할 수 없는 입력에 사용한다 →
 * CVE-2022-42889 (Text4Shell) 의 취약 API 가 실제 호출되는 "도달 가능" 경로.
 *
 * <p>반면 pom.xml 의 snakeyaml(CVE-2022-1471) 은 어디서도 import/호출하지 않는다 →
 * "도달 불가". 도달성 분석이 이 둘을 구분해 노이즈를 줄여야 한다.
 */
public class App {

  /** 도달 가능한 취약 사용: 외부 입력이 StringSubstitutor 보간으로 흐른다. */
  public static String interpolate(String userInput) {
    StringSubstitutor interpolator = StringSubstitutor.createInterpolator();
    return interpolator.replace(userInput);
  }

  public static void main(String[] args) {
    String input = args.length > 0 ? args[0] : "${date:yyyy}";
    System.out.println(interpolate(input));
  }
}
