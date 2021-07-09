/*import contracts.UserManagement;
import models.PublicInformation;
import org.hyperledger.fabric.contract.Context;
import org.hyperledger.fabric.shim.ChaincodeException;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public final class PublicInformationTest {
    @Nested
    class InvokeQueryPublicInformationTransaction {
        @Test
        public void whenPublicInformationExists() {
            UserManagement contract = new UserManagement();
            Context ctx = mock(Context.class);
            ChaincodeStub stub = mock(ChaincodeStub.class);

            when(ctx.getStub()).thenReturn(stub);
            when(stub.getStringState("TEST"))
                    .thenReturn("{\"data\":\"Datos test\"}");

            PublicInformation pubInfo = contract.getPublicInformation(ctx, "TEST");
            assertThat(pubInfo.getData()).isEqualTo("Datos test");
            assertThat(pubInfo.getStatus()).isEqualTo(false);
        }
        @Test
        public void whenPublicInformationNotExists() {
            UserManagement contract = new UserManagement();
            Context ctx = mock(Context.class);
            ChaincodeStub stub = mock(ChaincodeStub.class);

            when(ctx.getStub()).thenReturn(stub);
            when(stub.getStringState("TEST")).thenReturn("");

            Throwable thrown = catchThrowable(() -> {
                contract.getPublicInformation(ctx, "TEST");
            });

            assertThat(thrown).isInstanceOf(ChaincodeException.class).hasNoCause()
                    .hasMessage("Public information TEST does not exist");
        }
    }
}
*/