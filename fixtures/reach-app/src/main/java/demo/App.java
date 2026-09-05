package demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.text.StringSubstitutor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class App {
    public static void main(String[] args) { SpringApplication.run(App.class, args); }

    // (a) 취약 API: 사용자 입력이 interpolator 로
    public String interpolate(String userInput) {
        return StringSubstitutor.createInterpolator().replace(userInput);
    }

    // (b) 안전 API 만: 단순 POJO 역직렬화 (default typing 없음)
    public Config parse(String json) throws Exception {
        return new ObjectMapper().readValue(json, Config.class);
    }

    public static class Config { public String name; }
}
