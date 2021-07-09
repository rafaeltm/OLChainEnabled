package eu.olympus.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class Predicate {

	private String attributeName;
	private Operation operation;
	private Attribute value;
	private Attribute extraValue; //Needed for new "In range" predicate. There may be a better way to do this (for other possible operations too)
	
	public Predicate() {
	}
	
	public Predicate(String attributeName, Operation operation, Attribute value) {
		this.attributeName = attributeName;
		this.operation = operation;
		this.value = value;
	}

	public Predicate(String attributeName, Operation operation, Attribute value,Attribute extraValue) {
		this.attributeName = attributeName;
		this.operation = operation;
		this.value = value;
		this.extraValue=extraValue;
	}

	public String getAttributeName() {
		return attributeName;
	}

	public void setAttributeName(String attributeName) {
		this.attributeName = attributeName;
	}
	
	public Operation getOperation() {
		return operation;
	}
	
	public void setOperation(Operation operation) {
		this.operation = operation;
	}
	
	public Attribute getValue() {
		return value;
	}
	
	public void setValue(Attribute value) {
		this.value = value;
	}

	public Attribute getExtraValue() {
		return extraValue;
	}

	public void setExtraValue(Attribute extraValue) {
		this.extraValue = extraValue;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		Predicate predicate = (Predicate) o;
		return attributeName.equals(predicate.attributeName) && operation == predicate.operation && Objects.equals(value, predicate.value) && Objects.equals(extraValue, predicate.extraValue);
	}

	@Override
	public int hashCode() {
		return Objects.hash(attributeName, operation, value, extraValue);
	}

	@Override
	public String toString() {
		return "Predicate{" +
				"attributeName='" + attributeName + '\'' +
				", operation=" + operation +
				", value=" + value +
				", extraValue=" + extraValue +
				'}';
	}
}
