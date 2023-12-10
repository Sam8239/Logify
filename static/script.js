// On Form Submit Function Starts
const submitForm = () => {
	const formData = $("#myForm").serialize();

	$.ajax({
		type: "POST",
		url: "/search",
		data: formData,
		success: function (response) {
			handleSearchResponse(response);
		},
	});
};
// On Form Submit Function Ends

// OnClick Clear Button Starts
const onClear = () => {
	clearResultsTable();
	clearInput();
	$(".scrollToTop").attr("hidden", true);
};
// OnClick Clear Button Endss

// Update Results Function Starts
const updateResults = (data) => {
	clearResultsTable();

	if (data.results.length) {
		$(".scrollToTop").removeAttr("hidden");
		const { currentPage, pageSize, totalRecords, totalPages } = data;
		const startIndex = (currentPage - 1) * pageSize + 1;

		const table = buildResultsTable(data.results, startIndex);

		const pagination = buildPaginationControls(
			currentPage,
			pageSize,
			totalRecords,
			totalPages
		);
		const heading = "<h2>RESULTS</h2>";
		const exportButton =
			'<button id="exportButton" class="btn mb-3 btn-outline-light border-2">Export to CSV</button>';

		$("#results-container")
			.append(heading)
			.append(exportButton)
			.append(pagination)
			.append(table);
	} else {
		$(".scrollToTop").attr("hidden", true);
		$("#results-container").append("<h4>NO DATA AVAILABLE</h4>");
	}
};
// Update Results Function Ends

// Function to handle AJAX response
const handleSearchResponse = (response) => {
	if (response.com === "error") {
		clearResultsTable();
		$(".scrollToTop").attr("hidden", true);
		$("#results-container").append(
			"<h4>Error: Different Filters For Same Fields. Please Check all the Filters Again</h4>"
		);
	} else {
		updateResults(response);
	}
};

// Function to Build the Results Table Starts
const buildResultsTable = (results, startIndex) => {
	const table = $("<table>", { id: "table", class: "table table-success" });
	const thead = $("<thead>").append(
		"<tr><th scope='col'>S.NO</th><th scope='col'>Result</th></tr>"
	);
	const tbody = $("<tbody>", { id: "resultsBody" });

	results.forEach((result, index) => {
		const row = $("<tr>").append(
			`<th scope='row'>${index + startIndex}</th><td><pre>${JSON.stringify(
				result,
				null,
				1
			)}</pre></td>`
		);
		tbody.append(row);
	});

	return table.append(thead).append(tbody);
};
// Function to Build the Results Table Ends

// Function to build pagination controls Starts
const buildPaginationControls = (
	currentPage,
	pageSize,
	totalRecords,
	totalPages
) => {
	const startIndex = (currentPage - 1) * pageSize + 1;
	const endIndex = Math.min(startIndex + pageSize - 1, totalRecords);

	const pagination = $("<div>", {
		id: "pagination",
		class: "d-flex justify-content-between align-items-center mb-4",
	});
	const info = $("<div>").text(
		`Showing ${startIndex} to ${endIndex} of ${totalRecords} Records`
	);
	const btnGroup = $("<div>", { class: "btn-group" });

	const prevBtn = $("<button>", {
		type: "button",
		class: "btn btn-info me-4",
	}).text("Previous");

	const nextBtn = $("<button>", {
		type: "button",
		class: "btn btn-success",
	}).text("Next");

	// Attach click event listeners
	prevBtn.on("click", () => goToPage(currentPage - 1));
	nextBtn.on("click", () => goToPage(currentPage + 1));

	// Disable buttons based on current page
	prevBtn.prop("disabled", currentPage === 1);
	nextBtn.prop("disabled", currentPage === totalPages);

	return pagination
		.append(info)
		.append(btnGroup.append(prevBtn).append(nextBtn));
};
// Function to build pagination controls Ends

// Function to Get Filters Starts
const getFilters = () => {
	let filters = {};

	// Extract current filters from the form
	$("#myForm :input")
		.not("#selectInput")
		.each(function () {
			var key = $(this).attr("name");
			var value = $(this).val();
			filters[key] = value;
		});
	return filters;
};
// Function to Get Filters Ends

// Pagination Go to Page Function Starts
const goToPage = (page) => {
	let filters = getFilters();

	$.ajax({
		type: "POST",
		url: "/search",
		data: {
			query_text: $("#query_text").val(),
			...filters,
			page: page,
		},
		success: function (data) {
			updateResults(data);
		},
		error: function (error) {
			console.error("Error fetching data:", error);
		},
	});
};
// Pagination Go to Page Function Ends

// Clear Results Table Starts
const clearResultsTable = () => {
	$("#results-container").empty();
};
// Clear Results Table Ends

// Clear Input Functions Starts
const clearInput = () => {
	$("#myForm :input").not("#selectInput").val("");
};
// Clear Input Functions Ends

$(document).ready(function () {
	// Single or Multiple Filters Function Starts
	$("#toggle_filter").click(function () {
		// Toggle the visibility of the select field
		$("#select_field").toggle();

		// Check if the select field is visible
		if ($("#select_field").is(":visible")) {
			// If visible, hide other input fields except level
			$("#levelRow").show();
			$(".row:not(#levelRow)").hide();
			$(toggle_filter)[0].innerText = "Multiple Filters";
		} else {
			// If not visible, show all input fields
			$(toggle_filter)[0].innerText = "Single Filter";
			$(".row").show();
		}
	});
	// Single or Multiple Filters Function Ends

	// On Select Show Input Fields Starts
	$("#selectInput").change(function () {
		// Hide all rows
		$(".row").hide();

		// Show the selected row
		var selectedRowId = $(this).val() + "Row";
		$("#" + selectedRowId).show();
		clearInput();
	});
	// On Select Show Input Fields Ends
	// Date Picker Bootstrap Starts
	$("#start_date, #end_date").datepicker({
		format: "yyyy-mm-dd",
		autoclose: true,
		orientation: "top",
	});
	// Date Picker Bootstrap Ends
});

// Handle Export Button Click Starts
$(document).on("click", "#exportButton", function () {
	// Get the current filters
	var filters = getFilters();

	// Process the Filters
	$.ajax({
		type: "POST",
		url: "/search",
		data: {
			query_text: $("#query_text").val(),
			...filters,
		},
		success: function (data) {
			filters = data.filters;

			const params = new URLSearchParams(filters);
			const exportUrl = `/export?${params.toString()}`;

			// Open a new window to trigger the export
			window.open(exportUrl, "_blank");
		},
		error: function (error) {
			console.error("Error fetching data:", error);
		},
	});
});
// Handle Export Button Click Ends
