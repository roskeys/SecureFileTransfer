import java.io.File;

public class ReadTest {
    public static void main(String[] args) {
        File file = new File("test/test.py");
        System.out.println(file.exists());
    }
}
