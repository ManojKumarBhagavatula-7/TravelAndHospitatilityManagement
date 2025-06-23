package com.cts.SupportTicket.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SupportTicketRequestDTO {
    private int userId;
    private Integer assignedAgentId;
    private String issue;
	public int getUserId() {
		return userId;
	}
	public void setUserId(int userId) {
		this.userId = userId;
	}
	public Integer getAssignedAgentId() {
		return assignedAgentId;
	}
	public void setAssignedAgentId(Integer assignedAgentId) {
		this.assignedAgentId = assignedAgentId;
	}
	public String getIssue() {
		return issue;
	}
	public void setIssue(String issue) {
		this.issue = issue;
	}
	


   
}


