public class ichecker {
    public static void main(String[] args) throws Exception {

        switch (args[0]) {
            case "createCert":
                new createCert(args[2], args[4]);
                break;
            case "createReg":
                new createReg(args[2], args[4], args[6], args[8], args[10]);
                break;
            case "check":
                new check(args[2], args[4], args[6], args[8], args[10]);
                break;
        }
    }
}