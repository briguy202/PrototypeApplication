$(function () {
	$('#post-test').click(function () {
		alert("Document domain is: " + document.domain);

		$.post("http://app2.foo.com/api/values/5", function (data) {
			alert('Worked!');
		})
	});

	$('#get-test').click(function () {
		alert("Document domain is: " + document.domain);

		$.get("http://app2.foo.com/api/values/5", function (data) {
			alert('Worked!');
		})
	});
});
