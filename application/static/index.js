$(document).ready(function(){
	var scan_history = {};
	var url = "/scan_history";
	
	$.getJSON(url,function(data){
		scan_history = data;
		// console.log(scan_history);
		$('#scan_history_table').DataTable({
			data: scan_history,
		    columns: [
		    {
		        title: 'App Name',
		        render: function ( data, type, row ) { return '<a href="/reporting/report?id='+row['scan_id']+'">'+row['package_name']+'</a>'}
		    }, {
		        title: 'Version',
		        className: "text-center",
		        render: function ( data, type, row ) { return row['package_version'];}
		    }, {
		        title: 'Last Scan',
		        className: "text-center",
		        render: function ( data, type, row ) { return row['time_of_scan'];}
		    }, {
		        title: 'Vuln Count',
		        className: "text-center",
		        render: function ( data, type, row ) { return '<a class="btn btn-sm btn-danger" style="width:75px"><font size="0.1px">High</font> | '+row['results']['high']+'</a> &nbsp; <a class="btn btn-sm btn-warning" style="width:75px"><font size="0.1px">Med</font> | '+row['results']['medium']+'</a> &nbsp; <a class="btn btn-sm btn-info" style="width:75px"><font size="0.1px">Low</font> | '+row['results']['low']+'</a>';}
		    }, {
		        title: 'Status',
		        className: "text-center",
		        render: function ( data, type, row ) { 
		        	if (row['status'].includes("finished",0))
		        		return '<a class="btn btn-sm btn-success" style="width:80px; cursor:none"><span class="glyphicon glyphicon-ok"></span> '+row['status']+'</a>';

		        	if (row['status'].includes("error",0))
		        		return '<a class="btn btn-sm btn-danger" style="width:80px; cursor:none"><span class="glyphicon glyphicon-ban-circle"></span> '+row['status']+'</a>';

		        	return '<a class="btn btn-sm btn-primary" style="width:80px; cursor:none"><span class="glyphicon glyphicon-refresh"></span> scanning... </a>';
		        }
		    }, {
		        title: 'Report',
		        className: "text-center",
		        render: function ( data, type, row ) { 
		        	if (row['status'].includes("finished",0))
		        		return '<a class="btn btn-sm btn-primary" href="/reporting/report?id='+row['scan_id']+'"><span class="glyphicon glyphicon-eye-open" ></span></a> &nbsp; <a class="btn btn-sm btn-warning" data-toggle="tooltip" title="download" href="/reporting/download?id='+row['scan_id']+'"><span class="glyphicon glyphicon-download-alt" ></span></a>';
		        	return "--";
		        }
		    }]
		});
		$('#compare_history_table').DataTable({
			data: scan_history,
		    columns: [
		    {
		        title: 'App Name',
		        render: function ( data, type, row ) { return row['package_name'];}
		    }, {
		        title: 'Version',
		        render: function ( data, type, row ) { return row['package_version'];}
		    }, {
		        title: 'Last Scan',
		        render: function ( data, type, row ) { return row['time_of_scan'];}
		    }, {
		        title: 'Select',
		        render: function ( data, type, row ) { return '<div class="checkbox"><label><input name="scan_'+row['scan_id']+'" type="checkbox" value="'+row['scan_id']+'"></label>';}
		    }]
		});

	});
});