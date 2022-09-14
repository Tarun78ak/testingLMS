$(function() {
	'use strict';
	
  $('.form-control').on('input', function() {
	  var $field = $(this).closest('.form-group');
	  if (this.value) {
	    $field.addClass('field--not-empty');
	  } else {
	    $field.removeClass('field--not-empty');
	  }
	});

});

// Validation

// function checkInteger(){
// 	var userIn = document.getElementById("username").value;
// 	if (!isNaN(parseInt(userIn))){
// 		return true
// 	}
// 	else{
// 		alert("Error!")
// 		document.getElementById("username").value = ""
// 		document.getElementById("username").addEventListener("onchange",checkInteger);
// 		return false
// 	}
// }
