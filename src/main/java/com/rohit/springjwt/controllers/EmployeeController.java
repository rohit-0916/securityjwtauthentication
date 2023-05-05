package com.rohit.springjwt.controllers;

import com.rohit.springjwt.models.Employee;
import com.rohit.springjwt.repository.EmployeeRepository;
import com.rohit.springjwt.security.jwt.ResourceNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("api/employee")
public class EmployeeController {


    @Autowired
    private EmployeeRepository employeeRepository;

    @GetMapping("/all")
    public List<Employee> getAllEmployee(){
        return employeeRepository.findAll();
    }

    @PreAuthorize("hasRole('USER')or hasRole('MODERATOR') or hasRole('ADMIN')")
    @PostMapping("/create")
    public ResponseEntity<Employee> createEmployee(@RequestBody Employee employee){
        employeeRepository.save(employee);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}")
                .buildAndExpand(employee.getId()).toUri();
        return ResponseEntity.created(location).build();
    }

    @PreAuthorize("hasRole('MODERATOR' or hasRole('ADMIN'))")
    @GetMapping("/findbyid/{id}")
    public ResponseEntity<Employee> findById(@PathVariable long id){
        Employee emp = employeeRepository.findById(id)
                .orElseThrow(()->new ResourceNotFoundException("Employe not not witn id "+id));
        return  ResponseEntity.ok().body(emp);
    }

    @PreAuthorize("hasRole('MODERATOR') or hasRole('ADMIN')")
    @PutMapping("/update/{id}")
    public ResponseEntity<Employee> updateEmployee(@PathVariable long id,@RequestBody Employee employeedetails){
        Employee updateEmployee = employeeRepository.findById(id)
                .orElseThrow(()->new ResourceNotFoundException("employee not found with id "+id));
        updateEmployee.setFirstName(employeedetails.getFirstName());
        updateEmployee.setLastName(employeedetails.getLastName());
        updateEmployee.setEmailId(employeedetails.getEmailId());
        updateEmployee.setPhoneNumber(employeedetails.getPhoneNumber());

        employeeRepository.save(updateEmployee);
        return ResponseEntity.ok(updateEmployee);
    }
    @PreAuthorize("hasRole('MODERATOR') or hasRole('ADMIN')")
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<HttpStatus> deleteEmployee(@PathVariable long id){
        Employee employee  = employeeRepository.findById(id)
                .orElseThrow(()-> new ResourceNotFoundException("employee not exist with id "+id));
        employeeRepository.delete(employee);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }
}
