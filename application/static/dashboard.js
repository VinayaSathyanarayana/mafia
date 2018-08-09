$(document).ready(function(){
    var graphs = [{
            "balloonText": "High:[[value]]",
            "fillAlphas": 0.3,
            "lineAlpha": 0.1,
            "type": "column",
            "valueField": "high"
        },{
            "balloonText": "Medium:[[value]]",
            "fillAlphas": 0.2,
            "lineAlpha": 0.1,
            "type": "column",
            "valueField": "medium"
        },{
            "balloonText": "Low:[[value]]",
            "fillAlphas": 0.3,
            "lineAlpha": 0.1,
            "type": "column",
            "valueField": "low"
        },{
            "balloonText": "Info:[[value]]",
            "fillAlphas": 0.3,
            "lineAlpha": 0.1,
            "type": "column",
            "valueField": "info"
        }];

    var colors = ["#d9534f","#f0ad4e","#5bc0de","#5cb85c"];

    console.log(data);
    console.log(graphs);

    var chart = AmCharts.makeChart("chartdiv3", {
        "theme": "light",
        "type": "serial",
        "dataProvider": data,
        "valueAxes": [{
            "stackType": "line",
            "unit": "%",
            "position": "left",
            "title": "No of Vulns",
        }],
        "startDuration": 5,
        "graphs": graphs,
        "plotAreaFillAlphas": 0.1,
        "depth3D": 60,
        "angle": 30,
        "categoryField": "package",
        "categoryAxis": {
            "gridPosition": "start"
        },
        "colors": colors,
        "export": {
            "enabled": false
         },
         "color": "white"
    });
    jQuery('.chart-input').off().on('input change',function() {
        var property    = jQuery(this).data('property');
        var target      = chart;
        chart.startDuration = 0;

        if ( property == 'topRadius') {
            target = chart.graphs[0];
            if ( this.value == 0 ) {
              this.value = undefined;
            }
        }

        target[property] = this.value;
        chart.validateNow();
    });
});