package models;

import org.hyperledger.fabric.contract.annotation.DataType;

@DataType
public enum EventType {
    INFORMATION, POLICY, REPORT,
}
