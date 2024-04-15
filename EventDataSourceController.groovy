package com.openprisetech
import com.openprisetech.core.exception.ErrorCodes
import com.openprisetech.core.exception.OPException
import com.openprisetech.enums.AuthType
import com.openprisetech.enums.DataLicenseType
import com.openprisetech.enums.DataStoreType
import com.openprisetech.enums.EntityType
import com.openprisetech.enums.Preference
import com.openprisetech.enums.UserPreferenceType
import com.openprisetech.events.EventDataSourceEvent
import com.openprisetech.quota.AppQuotaTracker
import com.openprisetech.utils.AuditEvent
import com.openprisetech.utils.DataServiceStatisticsUtils
import com.openprisetech.utils.ElasticSearchUtils
import com.openprisetech.utils.EventHandlerUtil
import com.openprisetech.utils.OPCommonConstants
import com.openprisetech.utils.TerminologyUtils
import grails.artefact.Artefact
import grails.async.*
import grails.converters.JSON
import groovy.json.*
import groovy.time.TimeCategory
import org.elasticsearch.action.search.SearchResponse
import org.elasticsearch.client.Client
import org.elasticsearch.index.query.BoolQueryBuilder
import org.elasticsearch.index.query.QueryBuilders
import org.elasticsearch.search.SearchHit
import org.elasticsearch.search.aggregations.AbstractAggregationBuilder
import org.elasticsearch.search.aggregations.AggregationBuilders
import org.elasticsearch.search.aggregations.BucketOrder
import org.elasticsearch.search.aggregations.bucket.terms.Terms
import org.elasticsearch.search.aggregations.metrics.avg.Avg
import org.elasticsearch.search.aggregations.metrics.cardinality.Cardinality
import org.elasticsearch.search.aggregations.metrics.max.Max
import org.elasticsearch.search.aggregations.metrics.min.Min
import org.elasticsearch.search.aggregations.metrics.sum.Sum
import org.elasticsearch.search.builder.SearchSourceBuilder
import org.elasticsearch.search.sort.SortBuilder
import org.elasticsearch.search.sort.SortBuilders
import org.elasticsearch.search.sort.SortOrder
import org.grails.web.json.JSONObject
import org.hibernate.criterion.CriteriaSpecification
import org.hibernate.jdbc.Expectation
import org.quartz.JobKey

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.openprisetech.core.exception.OPLogEntry
import com.openprisetech.core.exception.OPLogUtils
import org.apache.commons.logging.Log
import org.apache.commons.logging.LogFactory
import com.openprisetech.job.utils.SchedulerUtils
import com.openprisetech.rest.OpSecuredRestfulController
import com.openprisetech.security.Administrators
import com.openprisetech.security.RoleOrder
import com.openprisetech.security.User
import com.openprisetech.utils.OPRuleMarkerConstants
import com.openprisetech.utils.RuleConstants
import com.openprisetech.vo.ServiceResponse
import com.openprisetech.oauth.Oauth2Provider
import com.openprisetech.oauth.Oauth2Factory

import org.elasticsearch.search.aggregations.bucket.histogram.DateHistogramInterval
import org.elasticsearch.search.aggregations.bucket.histogram.Histogram

import com.openprisetech.utils.AssessmentUtils
import org.quartz.Trigger
import org.quartz.impl.triggers.CalendarIntervalTriggerImpl

import java.text.SimpleDateFormat
import java.util.concurrent.TimeUnit

@Artefact("Controller")
class EventDataSourceController extends OpSecuredRestfulController{
	private static final log = LogFactory.getLog(this)
	NotificationService notificationService
	EventDataSourceService eventDataSourceService
	def jsonRpcClientService
	def dataProcessingService
	def ELKService
	def dataSourceCRUDService
	//def quartzScheduler
	OPQuartzSchedulerService OPQuartzSchedulerService
	def alertService
	def dataPipelineService
	def dataAssessmentService
	def AuthService
	def snapshotService
	def userPreferenceService
	def appFactoryService
	UtilityService utilityService
	ProcessService processService
	static responseFormats = ['json', 'xml']

	EventDataSourceController(){
		super(EventDataSource)
	}

	@Override
	def index(Integer max) {
		
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		String tenantNameFilterStr = null
		if(params.tenantName && params.tenantName.toString().trim()){
			if(!isUserSuperAdmin()){
				render(status: 403, errors: 'TenantName Filter Forbidden') as JSON
				return
			}
			tenantNameFilterStr = params.tenantName.toString().trim()
		}
		
		def tenantName = tenantService.userTenant
		def user = tenantService.currentUser
		RoleOrder userRole = user.role.authority as RoleOrder
		
		// users can only see data sources if he is an Manager or above
		if(!isUserDataAdminOrHigher()) {
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}
		
		OPLogEntry entry = OPLogEntry.getOPLogEntry(user.username, tenantName)
		OPLogUtils.logStartInfo(log, entry)
		
		def pageSize = params.pageSize ? params.pageSize.toInteger() : 10
		def pageNum = params.page ? params.page.toInteger() : 1
		def cols = params.cols ? params.list("cols") : []
		def allDsRequired = params.allDsRequired ? params.allDsRequired : false
		def manualUpdate = params.manualUpdate == 'true' ? Boolean.TRUE : params.manualUpdate == 'false' ? Boolean.FALSE : null
		def includeOpenDS = params.includeOpenDatasource == "true"? Boolean.TRUE:  Boolean.FALSE
		boolean showShadow = params.showShadow ? (params.showShadow.toString().toLowerCase() == "true") : false
		if(showShadow)
			showShadow = dataPipelineService.isShadowVisible(user, showShadow)
		if(!(allDsRequired  && cols && cols.size() <= 10)){
			params.max = Math.min(pageSize ?: 10, 1000)
			params.offset = ((pageNum - 1) * pageSize)
		}
		def q = params.q
		def c = EventDataSource.createCriteria()
		if(showShadow && userRole.value == RoleOrder.ROLE_SUPPORT_ADMIN.value) { // if showshadow is true and lggedin user is support admin always apply filter with current tenant
			tenantNameFilterStr = tenantName
		}
		def isDataStore = params.isDataStore == 'true' ? true : params.isDataStore == 'false' ? false : null
		OPLogUtils.logStartStepInfo(log, entry, "QUERY")
		def results = c.list(params) {
			if(cols){
				resultTransformer(CriteriaSpecification.ALIAS_TO_ENTITY_MAP)
				projections{
					cols.each{
						property(it,it)
					}
					property("id","id")
					property("tenantName","tenantName")
				}
			}
//			eq("tenantName", tenantName)
			if(tenantNameFilterStr) {
				eq("tenantName", tenantNameFilterStr)
			}else{
				eq("tenantName", tenantName)
			}
			ne("status", "Deleted")
			ne("status", "Hidden")
			if(q){
				ilike("name", "%" + q + "%")
			}
			if(isDataStore != null){
				eq("isDataStore",isDataStore as boolean)
			}
			if(manualUpdate != null){
				eq("allowManualUpdate", manualUpdate)
			}
			/*if(!includeOpenDS){
				ne("isOpenDatasource", true)
			}*/
			if (!showShadow) {
				eq("visibility", "User")
			}

			order("name", "asc")
		}
		OPLogUtils.logEndStepInfo(log, entry)
		
		def totalCount = results.totalCount		
		// getting a normal object so we can add what we want...
		def json = results as JSON
		def resultsObj = new JsonSlurper().parseText(json.toString())
		def retVal = []
		
		OPLogUtils.logStartStepInfo(log, entry, "RULE_ORDER")

		resultsObj.each{
			if(it.dataProvider) {
				def provider = Oauth2.load(it.dataProvider.id)
				it.dataProvider.provider = provider.provider
				it.dataProvider.isValid = provider.isValid
			}
			
			if(it.authMethod) {
				def provider = AuthMethod.load(it.authMethod.id)
				it.authMethod.provider = provider.provider
				it.authMethod.isValid = provider.isValid
			}

			if(it.dataSourceAdmin){
				it.isAdmin = Administrators.isUserAdmin(user, 'DataSource', it.id as long, it.tenantName)
			}
			
			if(!cols || cols.contains("purgeAfterPipelineRun")){
				def dsp = DataSourcePipeline.findByDatasourceId(it.id)
				it.put("purgeAfterPipelineRun", dsp?.pipelineId)
			}
			
			// Hiding datasources which are generated by shadow pipelines
			if(!cols || cols.contains("isDataStore") || it.isDataStore){
				it.pipelineName = ''
				it.order = ''
				
				
				def rulePipeline = dataPipelineService.getParentRuleAndPipeline(EventDataSource.load(it.id))
				if(rulePipeline){
					def pipeline = rulePipeline.get("pipeline")
					def dataStoreRule = rulePipeline.get("rule")
					
					if(pipeline && dataStoreRule){
						it.pipelineName = pipeline.name
						def orders = JSON.parse(pipeline.ruleOrder)
						for(def i = 0; i < orders.size(); i++){ // find current rule order in the pipeline
							if( orders[i].ruleId == dataStoreRule.id){
								it.order =  orders[i].order
								break
							}
						}
					}
				}
					
			}
			it.scheduleStatus = 'Disabled'
			def wkflws = eventDataSourceService.getDatasourceWorkflows(it.id, "Import")
			if (wkflws) {
				for (def wkflw : wkflws) {
					if (wkflw.status.equals("Active")) {
						it.scheduleStatus = 'Active'
						break
					}
				}
			}
			
			retVal << it
//			def item = it
//			if(!it.isAdmin) {
//				isAdminPromise[item.id +'.isUserAdmin'] = {
//					item.isAdmin = Administrators.isUserAdmin(user, 'DataSource', item.id, item.tenantName)
//					item
//				}
//			}
			
//			isAdminPromise[item.id +'.admins'] = {
//				item.admins = Administrators.getAdmins('DataSource', item.id, item.tenantName)
//				item
//			}
			
//			it.archiveDetails = snapshotService.getListOfAvailArchives(it)
		}
	
		OPLogUtils.logEndStepInfo(log, entry)
		OPLogUtils.logEndInfo(log, entry)
		
//		def promisesResult = isAdminPromise.get()
		respond total:totalCount, data:retVal
	}

	def validateSchema(){

		OPLogEntry entry = OPLogEntry.getOPLogEntry()
		OPLogUtils.logStartStepInfo(log, entry, "VALIDATING_REQUIRED_PARAMS_FOR_SCHEMA_VALIDATION")
		if(!isUserAuthorized()) {
			return renderErrorResponse(401, 'Unauthorized')
		}

		def tenantName = tenantService.userTenant
		def user = tenantService.currentUser
		RoleOrder userRole = user.role.authority as RoleOrder

		if(userRole.value < RoleOrder.ROLE_ADMIN.value) {
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}


		def authType
		def dsId = params.dsId ? params.dsId.toLong() : null
		def authId = params.oauth2Id ? params.oauth2Id.toLong() : (params.authMethodId ? params.authMethodId.toLong() : null)
		def folder = params.folder ?: null
		def selectedFile = params.selectedFile?: null
		def headerLineNumber = params.headerLine? params.headerLine.toLong() : null
		def dataStartsFrom = params.dataStartsFrom? params.dataStartsFrom.toLong() : null
		def delimiter = params.delimiter ?: null
		def headerBasedImport = params.importFieldsByName ? params.importFieldsByName.toBoolean() : null

		// If there's no DS id sent AND one of the required params are missing
		if(!dsId && !(authId && folder && selectedFile && params.headerLine && params.dataStartsFrom && delimiter && params.importFieldsByName)){
			return renderErrorResponse(400, "Required parameters missing.")
		}

		// For existing ds, check if there are any required params missing.
		if(dsId && !(authId && folder && params.headerLine && params.dataStartsFrom && delimiter && params.importFieldsByName)){
			return renderErrorResponse(400, "Required parameters missing.")
		}

		// Validating Data Source for correct DS id which belongs to the DS Admin's tenant.
		if(dsId){
			def ds = EventDataSource.findByIdAndTenantName(dsId, tenantName)
			if(!ds) return renderNotFoundErrorResponse('Data source')
		}

		// Can't validate schema if there are no headers in file to reference(for import by name case).
		if(headerLineNumber < 1 && headerBasedImport){
			return renderErrorResponse(400, "Header(Column header) line should be greater than 0 to validate the schema")
		}

		// Validating Oauth/AuthMethod details.
		if(params.oauth2Id){
			def oauth = Oauth2.findByIdAndTenantName(authId, tenantName)
			if(!oauth || oauth.status == "Deleted") {
				return renderNotFoundErrorResponse("Credential")
			}
			authType = "Oauth2"
		} else if(params.authMethodId){
			def authMethod = AuthMethod.findByIdAndTenantName(authId, tenantName)
			if(!authMethod || authMethod.status == "Deleted"){
				return renderNotFoundErrorResponse("Credential")
			}
			authType = "AuthMethod"
		}

		OPLogUtils.logAdditionalPayloadInfo(log, entry, "FINISHED_VALIDATING_REQUIRED_PARAMS", [:])
		OPLogUtils.logEndStepInfo(log, entry)

		def retVal = [:]
		try{
			retVal = eventDataSourceService.validateSchema(authId, authType, dsId, folder, selectedFile, headerLineNumber,
					dataStartsFrom, delimiter, headerBasedImport)
		}catch(Exception e){
			return renderException(e)
		}

		render retVal as JSON
	}
	
	def getAllDataSourcesOptimized(){
		
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		String tenantNameFilterStr = null
		if(params.tenantName && params.tenantName.toString().trim()){
			if(!isUserSuperAdmin()){
				render(status: 403, errors: 'TenantName Filter Forbidden') as JSON
				return
			}
			tenantNameFilterStr = params.tenantName.toString().trim()
		}
		
		def tenantName = tenantService.userTenant
		def user = tenantService.currentUser
		RoleOrder userRole = user.role.authority as RoleOrder
		
		// users can only see data sources if he is an Manager or above
		if(userRole.value < RoleOrder.ROLE_MANAGER.value) {
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}

		OPLogEntry entry = OPLogEntry.getOPLogEntry(user.username, tenantName)
		OPLogUtils.logStartInfo(log, entry)
		
		boolean showShadow = params.showShadow ? (params.showShadow.toString().toLowerCase() == "true") : false
		if(showShadow)
			showShadow = dataPipelineService.isShadowVisible(user, showShadow)

		def c = EventDataSource.createCriteria()
		if(showShadow && userRole.value == RoleOrder.ROLE_SUPPORT_ADMIN.value) { // if showshadow is true and loggedin user is support admin always apply filter with current tenant
			tenantNameFilterStr = tenantName
		}

		OPLogUtils.logStartStepInfo(log, entry, "QUERY")
		def results = c.list() {
			resultTransformer(CriteriaSpecification.PROJECTION)
			projections{
				// Do not change this order. It impacts results
				property('id')
				property('name')
				property('isDataStore')
				property('allowManualUpdate')
				property('timestampField')
				property('storeType')
			}
			
			if(tenantNameFilterStr) {
				eq("tenantName", tenantNameFilterStr)
			}else{
				eq("tenantName", tenantName)
			}
			ne("status", "Deleted")
			ne("status", "Hidden")
			if (!showShadow) {
				eq("visibility", "User")
			}
			order("name", "asc")
		}
		OPLogUtils.logEndStepInfo(log, entry)
		
		def totalCount = results.size
		def retVal = []

		OPLogUtils.logStartStepInfo(log, entry, "RULE_ORDER")
		def dsPipelineOrderMap = dataPipelineService.getPipelineRules(tenantName)
		results.each{
			def item = [:]
			item.id = it[0]
			item.name = it[1]
			item.isDataStore = it[2]
			item.allowManualUpdate = it[3]
			item.timestampField = it[4]
			item.storeType = it[5]
			def pipelineOrder = dsPipelineOrderMap.get(item.id as Long)
			if(pipelineOrder){
				item.pipelineName = pipelineOrder.pipelineName
				item.order =  pipelineOrder.order
			} else {
				item.pipelineName = ''
				item.order = ''
			}
			retVal << item
		}
	
		OPLogUtils.logEndStepInfo(log, entry)
		OPLogUtils.logEndInfo(log, entry)
		respond total:totalCount, data:retVal
	}

	def getAllExternalDataSources() {
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}

		def tenantName = tenantService.userTenant
		def user = tenantService.currentUser
		RoleOrder userRole = user.role.authority as RoleOrder

		if(userRole.value <= RoleOrder.ROLE_ADMIN.value) {
			renderErrorResponse(403, 'Forbidden')
			return
		}

		List retVal = []
		def datasourceCriteria = EventDataSource.createCriteria()
		def results = datasourceCriteria.list() {
			eq("tenantName", tenantName)
			ne("status", "Deleted")
			eq("visibility", "User")
			ne("dataFormat", "SYSTEM")
			eq("allowManualUpdate", false)
			eq("isDataStore", false)
		}

		results.each{
			def provider = null
			if (it.dataProvider) provider = it.dataProvider.provider
			else if (it.authMethod) provider = it.authMethod.provider
			retVal << [id: it.id, name: it.name, provider: provider]
		}
		render retVal as JSON

	}
	
	
	def isAdmin(){
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		String tenantNameFilterStr = null
		if(params.tenantName && params.tenantName.toString().trim()){
			if(!isUserSuperAdmin()){
				render(status: 403, errors: 'TenantName Filter Forbidden') as JSON
				return
			}
			tenantNameFilterStr = params.tenantName.toString().trim()
		}
		
		def tenantName = tenantService.userTenant
		def user = tenantService.currentUser
		RoleOrder userRole = user.role.authority as RoleOrder
		
		// users can only see data sources if he is an Manager or above
		if(userRole.value < RoleOrder.ROLE_MANAGER.value) {
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}
		
		OPLogEntry entry = OPLogEntry.getOPLogEntry(user.username, tenantName)
		
		def dsId = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		
		def isAdmin = Administrators.isUserAdmin(user, 'DataSource', dsId as long, tenantName)

		OPLogUtils.logAdditionalPayloadInfo(log, entry, "isAdmin for EDS " + dsId, isAdmin)
		
		render isAdmin
	}
	
	def getDSScheduleStatusMap(String tenantName, String action){
		def dsScheduleStatusMap = [:]
		def c = Process.createCriteria()
		def result = c.listDistinct {
		 eq('status', "Active")
		  entities {
			 eq("entityType", "DataSource")
			 if(action){
				 eq('action', action)
			 }
		  }
		}
		result.each{ process ->
			process.entities.each{ entity ->
				if(entity.entityType  == "DataSource"){
					dsScheduleStatusMap.put(entity.entityId as Long, 'Active')
				}
			}
		}
		return dsScheduleStatusMap
	}	
	
	@Override
	def save() {
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		def props = getParametersToBind()
		if(!userAllowedAction("save", tenantService.currentUser, props)) {
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}
		Gson gson = new Gson();
		HashMap m = gson.fromJson( props.toString(), HashMap.class)
		EventDataSource ds
		try{
			ds = eventDataSourceService.createDataSource(m)
		}
		catch(Exception e){
			log.error("Data source creation failed with error: ${e.getMessage()}", e)

			if(e.getMessage() !=null && e.getMessage().equals("NULL_OR_BLANK_ATTR_NAME")){
				render(status: 400, errors: 'NULL_OR_BLANK_ATTR_NAME') as JSON
				return
			}
			else{
				render(status: 400, errors: 'CreationFailed') as JSON
				return
			}
		}
		
		if(ds==null){
			render(status: 400, errors: 'CreationFailed') as JSON
			return
		}
		
		postSave("save", ds)
		
		render ds as JSON
	}

	/**
	 * To create System data sources
	 * @return
	 */
	def createSystemDataSource() {

		if(!isUserAuthorized()) {
			return renderErrorResponse(401, 'Unauthorized' )
		}

		if(!isUserSuperAdmin()) {
			return renderErrorResponse(403, 'Forbidden' )
		}

		def props = getParametersToBind()

		if(!userAllowedAction("save", tenantService.currentUser, props)) {
			return renderErrorResponse(403, 'Forbidden' )
		}

		Map m = new JsonSlurper().parseText(props.toString())
		EventDataSource ds
		try{
			ds = eventDataSourceService.createDataSource(m,false)
		} catch(Exception e){
			if(e.getMessage() !=null && e.getMessage().equals("NULL_OR_BLANK_ATTR_NAME")){
				return renderErrorResponse(400, 'NULL_OR_BLANK_ATTR_NAME' )
			} else{
				return renderErrorResponse(400, 'CreationFailed' )
			}
		}

		if(ds==null){
			return renderErrorResponse(400,'CreationFailed')
		}

		postSave("save", ds)

		render ds as JSON
	}

	@Override
	def update() {
		def dsId = params.id
		if (eventDataSourceService.isDsImporting(dsId)) {
			def details = [:]
			details << ['error_details': 'This data source is currently importing and changes cannot be saved. Please stop import and ensure the import process is stopped before saving the changes.']
			details << ['error_code': ErrorCodes.FAILED_TO_UPDATE_DATASOURCE]
			return renderErrorResponse(409, 'This data source is currently importing and changes cannot be saved. Please stop import and ensure the import process is stopped before saving the changes.', details)
		}
		OPLogEntry entry = OPLogEntry.getOPLogEntry()
		EventDataSource ds= EventDataSource.get(dsId)
		def user = tenantService.currentUser
		
		def props = getParametersToBind()

		Gson gson = new Gson()
		HashMap m = gson.fromJson(props.toString(), HashMap.class)

		def providerName = m.dataProvider? m.dataProvider.provider : m.authMethod? m.authMethod.provider: null
		def isProviderCloudStoreType = false
		if(providerName){
			isProviderCloudStoreType = eventDataSourceService.isProviderCloudStorageType(providerName)
		}
		// For schema validation, will update this value with new FileName and other following details.
		if(m.schemaInformation && isProviderCloudStoreType){
			if(m.schemaInformation instanceof String){
				// Ignoring this field if the value sent from UI without stringifying.
				def schemaInformation = (new JsonSlurper()).parseText(m.schemaInformation)
				SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
				schemaInformation.put("lastUpdated", sdf.format(new Date()))
				schemaInformation.put("lastUpdatedBy", user.impersonatedBy? user.impersonatedBy: user.username)
				m.schemaInformation = JsonOutput.toJson(schemaInformation)
				props.schemaInformation = m.schemaInformation
			}else{
				OPLogUtils.logAdditionalPayloadWarn(log, entry, "SCHEMA_INFORMATION_IS_NOT_STRINGIFIED", [dsID: dsId])
			}
		}
		if(m.containsKey("allowManualUpdate")){
			if(m.get("allowManualUpdate")){
				def wkflws = eventDataSourceService.getDatasourceWorkflows(dsId as long, null)
				if(wkflws){
					response.status = 400
					def message = ["errors": 'MANUAL_UPDATE_NOT_ALLOWED_HAS_WORKFLOWS']
					render  message as JSON
					return
				}
				try {
					//name and storeType of MDS created from dedupe and export create manual ds tasks are not allowed to change
					String storeType = ds.storeType?.value
					if(storeType && (storeType.equals(DataStoreType.REVIEW_DEDUP_DS.value) || storeType.equals(DataStoreType.EXPORT_MANUAL_DS.value))){
						if((m.get("name")!=ds.name) ||(m.get("storeType") != storeType)){
							OPLogUtils.logAdditionalPayloadError(log, entry, "UPDATING_MANUAL_DATA_SOURCE", [manualDatasoureId :ds.id, errorMessage: " name and storeType not allowed to change"])
							return renderErrorResponse(403, "name/storetype not allowed to change")
						}
					}
				} catch (Exception e){
					OPLogUtils.logAdditionalPayloadErrorStack(log, entry, "UPDATING_MANUAL_DATA_SOURCE", [manualDatasoureId :ds.id], e)
					return renderErrorResponse(500,"Update failed")
				}
			} else {
				if(ds.allowManualUpdate) {
					def apps = appFactoryService.getEntityAssociatedApps([dsId.toString()], EntityType.EventDataSource)
					if (apps?.totalCount) {
						response.status = 409
						def message = ["errors": 'The Manual data source is not allowed to change to normal data source because it is being used in the app factory.']
						render message as JSON
						return
					}
				}
			}
		}
		//check for OP headers if its field order is not -1 make it to -1
		for(def opHeader: OPCommonConstants.OP_DATASOURCE_HEADERS){
			def opAttr = props.attributes.find{it.originFieldName == opHeader}
			if(opAttr && opAttr.fieldOrder != -1){
				opAttr.fieldOrder = -1
			}
		}
		//to check attrs have dupe order and name
		eventDataSourceService.validateDsAttrs(props.attributes, dsId as Long)


		if(m.containsKey('dataLicenseType') && ds.dataLicenseType != m.dataLicenseType ){

			// Only support admin can update data license type
			if(!isUserSupportAdmin()){
				return renderErrorResponse(403,
						"User does not have write access to the field: 'dataLicenseType'")
			}

			if(m.dataLicenseType && !(DataLicenseType.values().find {it.value() == m.dataLicenseType})){
				return renderErrorResponse(400, "Invalid data for field: 'dataLicenseType'")
			}

		}

		if(m.containsKey('filterQuery')){

			boolean purgeBeforeUpdate = params.purgeAndUpdate? params.purgeAndUpdate.toBoolean(): false

			if(purgeBeforeUpdate){
				def purge = eventDataSourceService.purgeDataSource(ds)
				if (purge.status != 200) {
					log.error("Datasource Filter Update - could not purge datasource, error : ${purge}")
					renderErrorResponse(409, 'Datasource Filter Update - could not purge datasource, error : ' + purge)
				}
			}else if( m.get('filterQuery') && m.get('filterQuery') != '' && !(eventDataSourceService.isEventDataSourceEmpty(ds))){
				def details = [:]
				details << ['error_details': 'Filter cannot be updated as Datasource is having records, Datasource needs to be purged']
				details << ['error_code': ErrorCodes.NEEDS_DATASOURCE_PURGE_FOR_FILTER_QUERY_UPDATE]
				renderErrorResponse(ErrorCodes.NEEDS_DATASOURCE_PURGE_FOR_FILTER_QUERY_UPDATE, 'Filter cannot be updated as Datasource is having records, Datasource needs to be purged', details)
			}

		}

		super.update()
	}


	
	@Override
	def show() {

		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		def ds = EventDataSource.get(params.id)
		
		if(!ds || ds.status == 'Deleted' || ds.status == 'Hidden') {
			render(status: 404, errors: 'Not Found') as JSON
			return
		}
		
		def tenantName = tenantService.userTenant
		def user = tenantService.currentUser
		RoleOrder userRole = user.role.authority as RoleOrder
		
		if(userRole.value < RoleOrder.ROLE_MANAGER.value || ds.tenantName != tenantName) {
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}
		
		def resultsObj = ds as JSON
		
		resultsObj = new JsonSlurper().parseText(resultsObj.toString())

		if(ds.importAlert){
			resultsObj.importAlert = ds.importAlert.getDetailsForDisplay()
		}

		def provider
		if(resultsObj.dataProvider) {
			provider = Oauth2.load(resultsObj.dataProvider.id)
			resultsObj.dataProvider.id = provider.id
			resultsObj.dataProvider.provider = provider.provider
			resultsObj.dataProvider.isValid = provider.isValid
			resultsObj.dataProvider.isValidating = provider.isValidating
		}
		
		if(resultsObj.authMethod) {
			provider = AuthMethod.load(ds.authMethod.id)
			resultsObj.authMethod.id = provider.id
			resultsObj.authMethod.provider = provider.provider
			resultsObj.authMethod.isValid = provider.isValid
			resultsObj.authMethod.isValidating = provider.isValidating
		}
		
//		if(resultsObj.scheduleStatus == 'Active') {
//			def time = eventDataSourceService.getNextRun(ds.id, 1)
//			if(time) {
//				resultsObj.nextRun = time
//			}
//		}
		
		if(resultsObj.isDataStore){
			def dpRule = dataPipelineService.getParentRuleAndPipeline(ds)
			resultsObj["parentRule"] = dpRule.get("rule")
			resultsObj["parentPipeline"] = dpRule.get("pipeline")
			resultsObj["runningStatus"] = false
		} else {
			resultsObj.runningStatus = eventDataSourceService.isDsImporting(params.id)
		}


		def admins = Administrators.getAdmins(ds)
		if(admins) {
			resultsObj.admins = admins
		}

		// Adding tags
		resultsObj.tags = ds.tags
		resultsObj.isAdmin = Administrators.isUserAdmin(user, 'DataSource', ds.id, ds.tenantName)
		
		def dsp = DataSourcePipeline.findByDatasourceId(ds.id)
		resultsObj.put("purgeAfterPipelineRun", dsp?.pipelineId)
		
		if(ds.isArchiveAllowed && (ds.daysToArchive>0 || user.isOPSupportAdminOrHigher())){
			def availArchiveTypes = snapshotService.getAvailArchiveTypesByUser(user)
			resultsObj.archiveDetails = snapshotService.getListOfAvailArchives(ds, availArchiveTypes)
		}
		
		def stats = dataSourceCRUDService.getDataStatistics(ds, false)
		if(stats) {
			resultsObj.MB = stats.MB
			resultsObj.KB = stats.KB
			resultsObj.GB = stats.GB
			resultsObj.count = stats.count
		}
		
		if(ds && ds.dataAssessment) {
			DataAssessment da = ds.dataAssessment
			resultsObj.daEmailReport = da.emailReport
			resultsObj.daReportFrequency = da.reportFrequency.value
			resultsObj.daReportResult = da.lastReportRunResult
			resultsObj.daReportPDFId = da.lastReportPDFDoc?.id
			resultsObj.daStatus = da.getStatus()
			
			if(da.shadowPipeline) {
				resultsObj.daShadowPipelineId = da.shadowPipeline.id
			}
			
			Recipe cleanerRecipe = dataAssessmentService.lookupConfiguredRecipe(ds, "cleanerRecipeId")
			if(cleanerRecipe) {
				resultsObj.daCleanerPipelineId=cleanerRecipe.objectId
			}
		}
		def workflowArray = getListOfDSWorkFlowDetails(ds.id)
		resultsObj.workFlowDetails = workflowArray

		//to show SecurityKey info
		if (resultsObj.securityKey) {
			resultsObj.securityKey.name = ds.securityKey.name
			resultsObj.decryptFiles = true
		}

		render resultsObj as JSON
	}

	def getListOfDSWorkFlowDetails(dsID) {
		def workflowArray = []

		def wkflws = eventDataSourceService.getDatasourceWorkflows(dsID, null)
		if (wkflws) {
			for (def wkflw : wkflws) {
				if (wkflw.status.equals("Active")) {
					JobKey jobKey = new JobKey(wkflw.scheduleJobName)
					Trigger trigger = processService.getFirstTriggersOfJobIgnoresSleep(wkflw.scheduleJobName, wkflw.tenantName)
					if (trigger || wkflw.frequencyType == 'continuous') {
						def nextFireTime
						if (wkflw.frequencyType == 'continuous') {
							nextFireTime = 'Continuous'
						}
						else {
							if (trigger instanceof CalendarIntervalTriggerImpl) {
								nextFireTime = trigger.getFireTimeAfter(new Date())
							}
							else {
								nextFireTime = trigger.getFireTimeAfter()
							}
						}
						def action = ""
						wkflw.entities.each {
							if (it.entityId ==dsID && it.action == "Purge") {
								action = action + it.action
							} else if (it.entityId ==dsID && it.action == "Import") {
								action = action + it.action
							}
						}
						if (action.contains("Purge") && action.contains("Import"))
							workflowArray.add("name": wkflw.name, "nextRun": nextFireTime, "action": "Purge, Import")
						else if(action.contains("Purge"))
							workflowArray.add("name": wkflw.name, "nextRun": nextFireTime, "action": "Purge")
						else if(action.contains("Import"))
							workflowArray.add("name": wkflw.name, "nextRun": nextFireTime, "action": "Import")

					}
				}
			}
		}

		workflowArray.sort { it.nextRun }
		return workflowArray
	}

	def getArchiveDetails(){
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant
		def types = params.types ? params.list("types") : []
		
		// Only super admin and support admin can see all types of archives
		if(types && (user.isSupportAdmin() || user.isSuperAdmin())) {
			if(types instanceof List){
				types = types*.toUpperCase()
			}else{
				types = [snapshotService.ArchivalTypes.SUCCESS, snapshotService.ArchivalTypes.USER_CONFIGURED]
			}
		}else if(user.isSupportAdmin() || user.isSuperAdmin()){
			types = [SnapshotService.ArchivalTypes.SUCCESS, SnapshotService.ArchivalTypes.USER_CONFIGURED, SnapshotService.ArchivalTypes.INTERNAL]
		}else {
			types = [SnapshotService.ArchivalTypes.SUCCESS, SnapshotService.ArchivalTypes.USER_CONFIGURED]
		}
		
		
		def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		
		EventDataSource ds = EventDataSource.get(id)
		RoleOrder userRole = user.role.authority as RoleOrder
		
		if(ds && ds.tenantName != tenantName || userRole.value < RoleOrder.ROLE_MANAGER.value) {
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}
		
		if(!ds || ds.status == "Deleted"){
			render(status: 404, errors: 'Data source not found') as JSON
			return
		}

		def availableArchives = []
		if(ds.isArchiveAllowed && (ds.daysToArchive>0 || user.isOPSupportAdminOrHigher())){
			availableArchives = snapshotService.getListOfAvailArchives(ds, types)
		}
		
		render availableArchives as JSON

	}
	
	def getProviderNameAndStatus() {
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		def tenantName = tenantService.userTenant
		def user = tenantService.currentUser
		RoleOrder userRole = user.role.authority as RoleOrder
		
		def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		def dsInstance = EventDataSource.get(id)
		
		// users can only see data sources if he is an Admin or above
		if(userRole.value < RoleOrder.ROLE_ADMIN.value || !dsInstance || dsInstance.tenantName != tenantName) {
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}
		
		def retval = [:]
		if(dsInstance.dataProvider) {
			retval.id = dsInstance.dataProvider.id
			retval.providerType = "oauth2"
			retval.providerName = dsInstance.dataProvider.provider
			retval.isProviderValid = dsInstance.dataProvider.isValid
		}else if(dsInstance.authMethod) {
			retval.id = dsInstance.authMethod.id
			retval.providerType = "authMethod"
			retval.providerName = dsInstance.authMethod.provider
			retval.isProviderValid = dsInstance.authMethod.isValid
		}
		respond retval
	}
	
	def getTimestampDetails() {
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}

		def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		EventDataSource ds = EventDataSource.get(id)

		if(!ds || ds.status == "Deleted"){
			return renderNotFoundErrorResponse("Datasource")
		}

		if(!userAllowedAction("show", tenantService.currentUser, ds)){
			return renderErrorResponse(403, "Forbidden")
		}

		respond eventDataSourceService.getDsTimeStampDetails(ds)
	}
	
	def nextRun() {
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant
		def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		
		EventDataSource ds = EventDataSource.get(id);
		if(ds==null){
			render(status: 400, errors: 'CreationFailed') as JSON
			return
		}
		
		//if(ds.dataSourceAdmin.id != user.id || ds.tenantName != tenantName) {
		// no need to compare admin.  Anyone in the tenant can see the scheduled next run
		if(ds.tenantName != tenantName) {
			render(status: 403, errors: 'Forbidden') as JSON
			return;
		}
		
		def retval = eventDataSourceService.getNextRun(id, 1)
		if(!retval){
			retval = [:]
		}
		render retval as JSON

	}
	
	def getAllDataSourceSummary() {
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		String tenantNameFilterStr = null
		if(params.tenantName && params.tenantName.toString().trim()){
			if(!isUserSuperAdmin()){
				render(status: 403, errors: 'TenantName Filter Forbidden') as JSON
				return
			}
			tenantNameFilterStr = params.tenantName.toString().trim()
		}
		
		def tenantName = tenantService.userTenant
		def user = tenantService.currentUser
		RoleOrder userRole = user.role.authority as RoleOrder
		
		// users can only see data sources if he is an Admin or above
		if(userRole.value < RoleOrder.ROLE_ADMIN.value) {
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}
		
		def availArchiveTypes = snapshotService.getAvailArchiveTypesByUser(user)
		def pageSize = params.pageSize ? params.pageSize.toInteger() : 10
		def pageNum = params.page ? params.page.toInteger() : 1

		params.max = Math.min(pageSize ?: 10, 500)
		params.offset = ((pageNum - 1) * pageSize)

		def q = params.q
		def c = EventDataSource.createCriteria()

		def isDataStore = params.isDataStore == 'true' ? Boolean.TRUE : params.isDataStore == 'false' ? Boolean.FALSE : null
		def manualUpdate = params.manualUpdate == 'true' ? Boolean.TRUE : params.manualUpdate == 'false' ? Boolean.FALSE : null
		def administrativeDs = params.administrativeDs == 'true' ? Boolean.TRUE : params.administrativeDs == 'false' ? Boolean.FALSE : null

		def pipeline = null
		def results = []
		
		//// If we found pipelineId no need to use createCriteria
		//// Since we can find data sources from pipeline.rules
		if(params.pipelineId){
			if(params.pipelineId.isLong()){
			
				pipeline = DataPipeline.get(params.pipelineId as long)	
				
				if(!pipeline || pipeline.status == 'Deleted'){
					renderNotFoundErrorResponse(TerminologyUtils.PIPELINE)
					return
				}
				
				if((tenantName != pipeline.tenantName && !isSuperAdminAndSystemObject(pipeline)) 
					|| userRole.value < RoleOrder.ROLE_ADMIN.value ){
					render(status: 403, errors: 'Forbidden') as JSON
					return
				}
				
				if(!pipeline.ruleOrder){
					render([])
					return
				}
				
				//// Pipeline internal data sources should be in sorted based on the rule order
				def ruleOrder = JSON.parse(pipeline.ruleOrder).sort{it.order}
						
				ruleOrder.each{
					Rule rule = Rule.get(it.ruleId as long)
					if(rule.outputStore && rule.outputStore.status != 'Deleted') results.push(rule.outputStore)
					if(rule.residualStore && rule.residualStore.status != 'Deleted') results.push(rule.residualStore)
					if(rule.template.jsonKey == "reveal_data_rule"){  // reveal task creates multiple output stores each per vendor
						HashMap m = (Map) new JsonSlurper().parseText(rule.templateValues)
						Map revealRuleMap =  m.get(m.keySet().toList().find{!it.equals("filters")})
						List<Map> dataServiceDetails = revealRuleMap.get("data_services")
						for(Map dataServiceMap: dataServiceDetails) {
							if(dataServiceMap.containsKey("data_service_output_name")) {
								EventDataSource outputStore = EventDataSource.findByNameAndTenantName(dataServiceMap.get("data_service_output_name"), rule.tenantName)
								results.push(outputStore)
							}
						}
					}
				}

				results = results.toUnique { a, b -> a.id <=> b.id }

				if(params.q){
					results = results.findAll{ it.name.toLowerCase().contains(params.q.toLowerCase())}
				}
				
				//// Should support pagination.
				results = results.drop(params.offset).take(params.max)
			}else{
				render(status: 400, errors: 'Bad request') as JSON
				return
			}
		}else{
			// &showShadow=true for debug
			boolean showShadow = params.showShadow ? (params.showShadow.toString().toLowerCase() == "true") : false
			showShadow = dataPipelineService.isShadowVisible(user, showShadow)
			if(showShadow && userRole.value == RoleOrder.ROLE_SUPPORT_ADMIN.value) { // if showshadow is true and lggedin user is support admin always apply filter with current tenant
				tenantNameFilterStr = tenantName
			}

			def includeTags = []
			def excludeTags = []

			if(params.includeTags){

				if(params.includeTags instanceof String[]){
					includeTags = params.list("includeTags")
				}else{
					includeTags = [params.includeTags]
				}
			}

			if(params.excludeTags){
				if(params.excludeTags instanceof String[]){
					excludeTags = params.list("excludeTags")
				}else{
					excludeTags = [params.excludeTags]
				}
			}

			def matchMethod = params.matchMethod?:"AND"
			boolean ignorePreferences = params.ignorePreferences ? params.ignorePreferences.toBoolean() : true

			def userPreferredEntities = null
			if(!ignorePreferences) {
				if (includeTags || excludeTags) {
					userPreferredEntities = userPreferenceService.getMatchEntitiesByTags(user, ['includeTags': includeTags, 'excludeTags': excludeTags], matchMethod, EventDataSource.class)
				} else {
					userPreferredEntities = userPreferenceService.getUserPreferredEntities(user, Preference.DATASOURCE_CARDS, UserPreferenceType.TAGGING, EventDataSource.class)
				}
			}

			// If no entity matches with user preferences then return from here
			if(userPreferredEntities != null && userPreferredEntities.empty){
				return renderSuccessResponse([])
			}

			results = c.list(params) {
				if(userPreferredEntities != null){
					'in'("id", userPreferredEntities)
				}
				if(tenantNameFilterStr) {
					eq("tenantName", tenantNameFilterStr)
				}else{
					eq("tenantName", tenantName)
				}
				ne("status", "Deleted")
				ne("status", "Hidden")
				if(q){
					ilike("name", "%" + q + "%")
				}
				if(isDataStore != null){
					eq("isDataStore", isDataStore)
				}	
				if(manualUpdate != null){
					eq("allowManualUpdate", manualUpdate)	
				}

				if(administrativeDs != null){
					// for now we a have only assessment output stores under administrative Ds category
					if(administrativeDs)
						eq("storeType", DataStoreType.ASSESSMENT_DS)
					else{
						or{
							isNull("storeType")
							ne("storeType", DataStoreType.ASSESSMENT_DS)
						}
					}

				}

				if (!showShadow) {
					eq("visibility", "User")
				}
				order("name", "asc")
			}
		}
		
		
		def retval = []
		def allRunsPromise = new PromiseMap()
		results.each{
			def item = [:]
			item.id = it.id
			item.name = it.name
			item.description = it.description
			item.importInfo = it.importInfo
            item.updateInfo = it.updateInfo
			item.isDataStore = it.isDataStore
			item.isOpenDatasource = it.isOpenDatasource
			item.scheduleStatus = it.scheduleStatus
			item.isAdmin = Administrators.isUserAdmin(user, it)
			item.allowManualUpdate = it.allowManualUpdate
			item.daysToArchive = it.daysToArchive
			item.isArchiveAllowed = it.isArchiveAllowed
			item.dataAssessment = it.dataAssessment
			item.tags = it.tags
			item.dataFormat = it.dataFormat
			item.dpPath = it.dpPath
			item.decryptFiles = it.decryptFiles

			if(it.dataProvider) {
				def provider = Oauth2.load(it.dataProvider.id)
				item.oauth = [:]
				item.oauth.id = provider.id
				item.oauth.provider = provider.provider
				item.oauth.isValid = provider.isValid
				item.oauth.isValidating = provider.isValidating
			}
			
			if(it.authMethod) {
				def provider = AuthMethod.load(it.authMethod.id)
				item.authMethod = [:]
				item.authMethod.id = provider.id
				item.authMethod.provider = provider.provider
				item.authMethod.isValid = provider.isValid
				item.authMethod.isValidating = provider.isValidating
			}

			if(it.importOptions){
				Map importOptionsMap = new JsonSlurper().parseText(it.importOptions)
				// if one file import at a time option is enabled
				if(importOptionsMap.singleFileImportOpts){
					item._1FileAtaTime = true
				}
			}
						
//			if(it.scheduleStatus == 'Active' && allRuns) {
//				def nextRun = allRuns.find{it.dsId == item.id}
//				if(nextRun) item.nextRun = nextRun.nextRuns
//			}

			item.scheduleStatus='Disabled'
			def wkflws = eventDataSourceService.getDatasourceWorkflows(it.id, null)
			if(wkflws){
				for(def wkflw:wkflws){
					if(wkflw.status.equals("Active")){
							item.scheduleStatus = 'Active'
						break
					}
				}
			}
			def workflowArray = getListOfDSWorkFlowDetails(it.id)
			item.workFlowDetails = workflowArray
			item.storeType = it.storeType
			def rulePipeline = dataPipelineService.getParentRuleAndPipeline(EventDataSource.load(it.id))
			if(rulePipeline){
				def dataStoreRule = rulePipeline.get("rule")
				pipeline = rulePipeline.get("pipeline")
				if(pipeline && dataStoreRule){
					item.runMode  = pipeline.runMode
					item.rule = [:]
					item.rule.id = dataStoreRule.id
					item.rule.name = dataStoreRule.name
					item.rule.status = dataStoreRule.status
					item.rule.pipelineName = pipeline ? pipeline.name : null
					item.rule.maxOrder = null
					item.rule.order = null
					item.rule.purgeOutputBeforeRun = dataStoreRule.purgeOutputBeforeRun

					def ruleOrders = pipeline ? JSON.parse(pipeline.ruleOrder): ""
					if(ruleOrders){
						item.rule.maxOrder = ruleOrders.size()
						for(def i = 0 ; i < ruleOrders.size() ; i++){ // find current rule order in the pipeline
							if( ruleOrders[i].ruleId == dataStoreRule.id){
								item.rule.order =  ruleOrders[i].order
								break
							}
						}
					}
				}
			}
			
			allRunsPromise[item.id +'.stats'] = {
				EventDataSource.withTransaction {
					def stats = dataSourceCRUDService.getDataStatistics(EventDataSource.read(item.id as long), false)
					item.archiveDetails = (!item.isDataStore && ( item.isArchiveAllowed && ( item.daysToArchive>0 || user.isOPSupportAdminOrHigher())))? snapshotService.getListOfAvailArchives(EventDataSource.read(item.id as long), availArchiveTypes) : []
					if (stats) {
						item.MB = stats.MB
						item.KB = stats.KB
						item.GB = stats.GB
						item.count = stats.count
					}
					return stats
				}
			}
			
			retval << item
		}
		
		def promisesResult = allRunsPromise.get()
		render retval as JSON
		
	}
	
	def getAllNextRun(tenantName) {
		def jsonRpcServerUrl = Configuration.findByNameAndType("jsonRpcServerUrl", "system")
		def now = new Date()
		
		def retval = null
		
		try {
			jsonRpcClientService.send(jsonRpcServerUrl.value, now.getTime(), "ds.nextRun", [tenantName: tenantName, next: 5])
		}catch(Exception e) {
		}
		
		return retval
	}
	
	def scheduleRun() {
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant
		def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		
		EventDataSource ds = EventDataSource.get(id);
		if(ds==null){
			render(status: 400, errors: 'CreationFailed') as JSON
			return
		}
		
		def userIsAdmin = Administrators.isUserAdmin(user, ds)
		if(!userIsAdmin) {
			userIsAdmin = ds.dataSourceAdmin.id == user.id
		}
		if(!userIsAdmin || ds.tenantName != tenantName) {
			render(status: 403, errors: 'Forbidden') as JSON
			return;
		}
		ds.scheduleStatus = 'Active'
		ds.allowManualUpdate = Boolean.FALSE 
		ds.save(flush:true);
		
		render doScheduleRun(id) as JSON
	}
	
	def runCleanupJob() {
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		if(!isUserSuperAdmin()) {
			render(status: 403, errors: 'Forbidden') as JSON
			return;
		}

		OPQuartzSchedulerService.triggerJob("Clean Outputstore Schedule Job", tenantService.getSuperTenant())
		render([message: 'SUCCESS'] as JSON)
	
	}
	
	def runCustomerInfoJob() {
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant
		def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		
		EventDataSource ds = EventDataSource.get(id);
		if(ds==null){
			render(status: 400, errors: 'CreationFailed') as JSON
			return
		}
		if(ds.dataSourceAdmin.id != user.id || ds.tenantName != tenantName) {
			render(status: 403, errors: 'Forbidden') as JSON
			return;
		}

		OPQuartzSchedulerService.triggerJob("DS " + ds.id  + " Schedule Job", tenantService.getSuperTenant())
		render([message: 'SUCCESS'] as JSON)
	
	}

	def runSyncDataSourceInfoJob() {
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}

		def tenantName = tenantService.userTenant
		def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1

		EventDataSource ds = EventDataSource.get(id);
		if(ds==null){
			render(status: 400, errors: 'CreationFailed') as JSON
			return
		}

		if(!isUserSuperAdmin() || ds.tenantName != tenantName) {
			render(status: 403, errors: 'Forbidden') as JSON
			return;
		}

		OPQuartzSchedulerService.triggerJob(ds.name, tenantService.getSuperTenant())
		render([message: 'SUCCESS'] as JSON)
	}
	
	def runNow() {
		try
		{
			if(!isUserAuthorized()) {
				render(status: 401, errors: 'Unauthorized') as JSON
				return
			}

			def user = tenantService.currentUser
			def tenantName = tenantService.userTenant
			def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1

			EventDataSource ds = EventDataSource.get(id)
			if(ds == null){
				render(status: 404, errors: 'Not Found') as JSON
				return
			}
			def userIsAdmin = Administrators.isUserAdmin(user, ds)
			if(!userIsAdmin) {
				userIsAdmin = ds.dataSourceAdmin.id == user.id
			}
			if(!userIsAdmin || ds.tenantName != tenantName) {
				render(status: 403, errors: 'Forbidden') as JSON
				return;
			}
			boolean reSync = params.reSync? params.reSync.toBoolean(): false
			boolean isReSyncDeleteDetectionOnly = (reSync && params.isReSyncDeleteDetectionOnly)? params.isReSyncDeleteDetectionOnly.toBoolean(): false
			boolean reSyncWithFilter = params.reSyncWithFilter? params.reSyncWithFilter.toBoolean(): false
			boolean isReSyncDeleteDetectionWithFilter = params.isReSyncDeleteDetectionWithFilter? params.isReSyncDeleteDetectionWithFilter.toBoolean(): false //edit here
			boolean isFilterEnabled = false
			if(reSyncWithFilter || isReSyncDeleteDetectionWithFilter){
				isFilterEnabled = true
				if(isReSyncDeleteDetectionWithFilter){
					reSync = true
					isReSyncDeleteDetectionOnly = true
				}
				else if(reSyncWithFilter){
					reSync = true
				}
			}
			def filterString = (params.filters?.size() > 0)? (new JsonSlurper().parseText(params.filters)): null
			def filterOperator = filterString? (filterString[0].operator? filterString[0].operator.toString():'') : ''
			Map filterDateValue = null
			if(filterString){
				if(filterString[0].values[0].size() == 2){

					def toDate = filterString[0].values[0].to_value? filterString[0].values[0].to_value.toString():''
					def fromDate = filterString[0].values[0].from_value? filterString[0].values[0].from_value.toString():''
					filterDateValue = [fromDate:fromDate, toDate:toDate]
				}else{
					def DateValue = filterString? (filterString[0].values[0].value? filterString[0].values[0].value.toString():'') : ''
					filterDateValue = [Date:DateValue]
				}
			}
			def filterField = filterString? (filterString[0].field? filterString[0].field.toString():'') : ''

			switch (filterOperator){
				case "equals":
					filterOperator = "="
					break
				case "greater_than":
					filterOperator = ">"
					break
				case "greater_than_or_equals":
					filterOperator = ">="
					break
				case "less_than":
					filterOperator = "<"
					break
				case "less_than_or_equals":
					filterOperator = "<="
					break
				default:
					break;
			}
			Map additionalParams
			if(isFilterEnabled == true){
				additionalParams = [reSync: reSync, isReSyncDeleteDetectionOnly: isReSyncDeleteDetectionOnly, isFilterEnabled: isFilterEnabled, filterOperator: filterOperator, filterDateValue: filterDateValue, filterField: filterField]
			}else{
				additionalParams = [reSync: reSync, isReSyncDeleteDetectionOnly: isReSyncDeleteDetectionOnly]
			}

			def retval = eventDataSourceService.importDS(ds , user, null, additionalParams, null)
			if(retval?.errors){
				if(retval.message == 'InsufficientServiceQuota') {
					render(status: 409, text: 'InsufficientServiceQuota') as JSON
					return
				} else {
					response.status = 409
					render([message: retval.message] as JSON)
					return
				}
			}
			render retval as JSON
		}
		catch( Exception ex){
			def maxretries=2
			def latetime= 5000 // means 5 seconds
			def retries=0
			while(retries< maxretries){
				try {
					TimeUnit.MILLISECONDS.sleep(latetime)
					def retval = eventDataSourceService.importDS(ds, user, null, additionalParams, null)
					if (retval?.errors) {
						if (retval.message == 'InsufficientServiceQuota') {
							render(status: 409, text: 'InsufficientServiceQuota') as JSON
							return
						} else {
							response.status = 409
							render([message: retval.message] as JSON)
							return
						}
					}
					render retval as JSON
					return
				}
				catch( Exception ex2){
					retries++;
					if(retries == maxretries){
						render(status:500, errors:'Reaching maximum retries') as JSON
						return
					}
				}
			}

		}
	}

	def cancelSchedule() {
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant
		def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		
		EventDataSource ds = EventDataSource.get(id)
		if(ds==null){
			render(status: 400, errors: 'CreationFailed') as JSON
			return
		}
		def userIsAdmin = Administrators.isUserAdmin(user, ds)
		if(!userIsAdmin) {
			userIsAdmin = ds.dataSourceAdmin.id == user.id
		}
		if(!userIsAdmin || ds.tenantName != tenantName) {
			render(status: 403, errors: 'Forbidden') as JSON
			return;
		}
		ds.scheduleStatus = 'Disabled'
		ds.allowManualUpdate = Boolean.FALSE
		ds.save(flush:true);
		
		render eventDataSourceService.doCancelSchedule(id) as JSON
	}

	
	def doScheduleRun(id){
		def user = tenantService.currentUser
		def jsonRpcServerUrl = Configuration.findByNameAndType("jsonRpcServerUrl", "system")
		
		def retval = [done:false]
		
		try {
			retval = jsonRpcClientService.send(jsonRpcServerUrl.value, id, "ds.schedule", [dsId: id, userId: user.id])
			if(retval == 'scheduled') {
				retval = [done: true]
			}else {
				retval = [done: false]
			}
		}catch(Exception e) {}
		
		return retval
	}

	@Override
	protected void postSaveEx(action, oldDs , newDs) {
		try {
			if (action == 'update') {
				if(!newDs.importAlert && oldDs.importAlert){
					ImportAlert alert = oldDs.importAlert
					alert.delete(flush: true, failOnError: true)
				}

				// Update assessment task output store name on data source name change's
				if(oldDs.name != newDs.name && newDs.dataAssessment && !newDs.statusDeleted){
					eventDataSourceService.updateAssessmentTaskOutputStore(newDs)
				}
			}
		}catch (Exception e){
			log.error("EventDataSourceController::postSaveEx Error while deleting importAlert for dsID: ${newDs.id}", e)
		}
	}

	@Override
	protected void postSave(action, object) {
		EventDataSource entity = object
		try {
			if(action == 'save' || action == 'update') {
				if(action == 'update' && entity.scheduleStatus == "Disabled") {
					eventDataSourceService.doCancelSchedule(entity.id)
				}else if(entity.scheduleStatus == "Active"){
					doScheduleRun(entity.id)
				}
				
				def props = getParametersToBind()
				def resultsObj = new JsonSlurper().parseText(props.toString())
				if(resultsObj.admins) {
					Administrators.setAdmins(resultsObj.admins, entity)
				}
				
 				if(entity.isDataStore.booleanValue() == false) {
					 // Check for required attributes 
					 // and add missing attributes
					 eventDataSourceService.addAssessmentRequiredFields(entity)

					 // run shadow pipe asynchronously
					 String shadowPipelineName = "SYS_DA_" + entity.name
					 ServiceResponse svcResp = dataAssessmentService.saveAndRunShadowPipeline(entity, shadowPipelineName, props)
					 if(svcResp && !svcResp.isSuccess()) {
						 log.error("Shadow Pipeline ${shadowPipelineName} creation/run failed: ${svcResp}!")
						 render(status: svcResp.status, text: svcResp.message) as JSON
						 return
					 }
					 log.info("Shadow Pipeline ${shadowPipelineName} creation/run completed!")
					 // update shadowpipeline - skip
				 }
				def dsp = DataSourcePipeline.findByDatasourceId(entity.id)
				if(resultsObj.containsKey("purgeAfterPipelineRun")){					
					String dpId = resultsObj.get("purgeAfterPipelineRun")					
					if(dpId && dpId.isLong()){						
						if(!dsp){
							dsp = new DataSourcePipeline()
							dsp.datasourceId = entity.id
							dsp.tenantName = resultsObj.tenantName							
						}						
						dsp.pipelineId = dpId as long							
						dsp.save(flush:true)
					}else if(dsp){
						dsp.delete(flush:true)
					}
				}				
			} else if(action == 'delete') {
				eventDataSourceService.doCancelSchedule(entity.id)
				
				Administrators.removeAll(entity, true)
				
				// TODO: delete shadowpipeline - skip validation
				def dsp = DataSourcePipeline.findByDatasourceId(entity.id)
				if(dsp){
					dsp.delete()
				}
			}
		}catch(Exception e) {
			log.error("Error in postSave method. Action: $action, Entity ID: ${entity?.id}. Message: ${e.getMessage()}", e)
		}
	}
	
	/**
	 * overriding the method that gets call for all actions.
	 * Only super admin can CRUD roles
	 */
	@Override
	protected boolean userAllowedAction(action, user, ds) {
		def dsProps = params.originalInstanceProperties
		def role = user.role
		
		// Super user is not allowed in this screen but if that were
		// the case, uncomment the code below
//		if(isUserSuperAdmin()) {
//			return true
//		}
		
		// if the tenant are not the same, the user cannot delete or update the other user whatsoever
		// save is taken care by the injection via the getParametersToBind method
		if((action=='delete'||action=="update"||action=="show") && user.tenantName != ds.tenantName) {
			return false
		}
		 
		def userIsAdmin = Administrators.isUserAdmin(user, ds)
		if(!userIsAdmin) {
			try {
				userIsAdmin = ds.dataSourceAdmin.id == user.id
			}catch(Exception e) {
				userIsAdmin = ds.dataSourceAdmin == user.id
			}
			
		}
		
		// The user is changing the admin for the service.  Check that the previous admin is the same as the current user
		if(action=="update" && !userIsAdmin) {
			return false
		}
		
		// if the current logon user is not the admin, the user cannot see the resource
		if((action=="delete" || action=="update") && !userIsAdmin) {
			return false
		}
		
		RoleOrder userRole = user.role.authority as RoleOrder
		
		if(action == "show" && userRole.value < RoleOrder.ROLE_ADMIN.value) {
			return false;
		}
		
		return true
	}
	
	/**
	 * The parameters that can be bound to a domain instance. Defaults to all, subclasses should override and customize the behavior
	 *
	 * @return The parameters
	 */
	@Override
	protected Map getParametersToBind() {
		JSONObject myparams = new JSONObject()
		if(request.JSON){
			myparams = request.JSON
			//inject the tenantName whenever an update or insert occurs
			myparams.tenantName = tenantService.userTenant
			if(myparams.containsKey('importInfo')) {
				myparams.remove('importInfo')
			}
			if(myparams.containsKey('updateInfo')) {
				myparams.remove('updateInfo')
			}
			// validate archive related changes before save
			if(myparams.daysToArchive > 0){
				myparams = validateArchivalOptions(myparams)
			}
		}

		return myparams
	}
	
	// This method is to validate archive options	
	def validateArchivalOptions(dsMap){
		
		def tenantObj = TenantInfo.findByTenantName(tenantService.userTenant)
		if(!tenantObj.boolArchives){
			dsMap.daysToArchive = 0
		}else{
			def maxArchiveLimit = Configuration.findByNameAndType("maxDatasourceArchivesLimit", "system")?.value?.toLong()?:7
			dsMap.daysToArchive = Math.min(dsMap.daysToArchive, maxArchiveLimit)
		}
		
		return dsMap
	}
	
	@Override
	def delete(){
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant
		def id = params.id ? params.id.toInteger() : -1
		
		EventDataSource ds = EventDataSource.get(id)
		if(ds==null){
			return renderNotFoundErrorResponse('Data source')
		}

		if (ds.dataFormat == 'SYSTEM') {
			return renderErrorResponse(403, 'Cannot delete system data source')
		}
		
		def userIsAdmin = Administrators.isUserAdmin(user, ds)
		if(!userIsAdmin) {
			userIsAdmin = ds.dataSourceAdmin.id == user.id
		}
		if(!userIsAdmin || ds.tenantName != tenantName) {
			render(status: 403, errors: 'Forbidden') as JSON
			return;
		}

		if (eventDataSourceService.isDsImporting(id)) {
			def details = [:]
			details << ['error_details': 'This data source is importing data currently. Please try after sometime.']
			details << ['error_code': ErrorCodes.FAILED_TO_DELETE_DATASOURCE]
			return renderErrorResponse(409, 'This data source is importing data currently. Please try after sometime.', details)
		}

		def apps = appFactoryService.getEntityAssociatedApps([id.toString()], EntityType.EventDataSource)
		if(apps?.totalCount > 0){
			return renderErrorResponse(405, "Datasource is used in app factory")
		}

		def retVal = eventDataSourceService.deleteDataSource(id)
		if(retVal?.get("status")?.equals("FAIL")){
			response.status = 400
			render retVal as JSON
			return
		}

		// Remove tags
		removeTags(ds)

		render "SUCCESS"
	}
	
	def createDataStore(){
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant
		def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		
		
		EventDataSource originalDS = EventDataSource.get(id)
		if(originalDS==null){
			render(status: 400, errors: 'CreationFailed') as JSON
			return
		}
		def userIsAdmin = Administrators.isUserAdmin(user, originalDS)
		if(!userIsAdmin) {
			userIsAdmin = originalDS.dataSourceAdmin.id == user.id
		}
		if(!userIsAdmin || originalDS.tenantName != tenantName) {
			render(status: 403, errors: 'Forbidden') as JSON
			return;
		}
		
		
		String props = getParametersToBind()
		

		Gson gson = new Gson()
		HashMap data = gson.fromJson(props, HashMap.class)

		String newDSName  = data.get("datastore_name")
		
		List<HashMap> attrsToAdd = data.get("attributes_to_add")
		
		List<String> attrsToDelete = data.get("attributes_to_delete")
		
		List<String> dsAttsToDelete = new ArrayList();
		
		
		List attributesToAdd = new ArrayList();
		
					
		EventDataSource eventDs = eventDataSourceService.createtDataStore(originalDS, newDSName, attrsToAdd, dsAttsToDelete,[:], true, true)
		
		render "SUCCESS"
	}
	
	def searchEventData(){
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant
		def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		
		RoleOrder userRole = user.role.authority as RoleOrder
		
		EventDataSource ds = EventDataSource.get(id)
		if(ds==null){
			render(status: 400, errors: 'CreationFailed') as JSON
			return
		}
		// users can only see data sources if he is an Admin or above
		if(userRole.value < RoleOrder.ROLE_MANAGER.value || 
			(ds.tenantName != tenantName && !isUserSuperAdmin())) {
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}
		
        def props = getParametersToBind()

        //def res = createResource(props)
        int page = Integer.parseInt(params.page)
        int size = Integer.parseInt(params.size)
		
		def sortBy = params.sortBy
		def sortOrd = params.sortOrder
		
		String sortDSAttr = "@timestamp"
		SortOrder sortOrder = SortOrder.ASC
		if(sortBy){
			 sortDSAttr = dataProcessingService.getDSAttribute(ds, sortBy)
			 String type = dataProcessingService.getDSAttributeType(ds, sortBy)
			 // Since we are exposing @OPDedupeSurviveRecID and that will not be analyzed
			 // We are adding second condition
			 if(type.equalsIgnoreCase("string") && !sortDSAttr.startsWith("@OP")){
				 sortDSAttr =sortDSAttr +RuleConstants.DS_ATTR_LOWERCASE_SUFFIX
			 }
		}
			 
		 if(sortOrd){
			 if(sortOrd.equals("asc")){
				 sortOrder = SortOrder.ASC
			 }
			 else{
				 sortOrder = SortOrder.DESC
			 }
		 }
		 
		  SortBuilder sortBuilder = SortBuilders.fieldSort(sortDSAttr).order(sortOrder)
		  if(sortDSAttr.equals("@timestamp")){
			  sortBuilder = SortBuilders.fieldSort(sortDSAttr).order(sortOrder).unmappedType("date")
		  }

		SearchSourceBuilder searchSourceBuilder = dataProcessingService.getELQueryObj(ds, props.toString(), null, null, null, user)

        List list = new ArrayList<>()
		HashMap aggValues =  new HashMap()
		def totalRecordsCount = 0
        try{
            int esLim = 32000
			Gson gson = new GsonBuilder().create();
			HashMap m = gson.fromJson( props.toString(), HashMap.class)
			ArrayList<Map> searchAggregation  = (ArrayList)m.get("search_aggregations")
			int from = (page-1)*size

			SearchResponse sr1 = ELKService.searchELData(searchSourceBuilder,[], size, ["from":from, "sort":sortBuilder], ds)
			totalRecordsCount = sr1.getHits().totalHits
            java.util.Iterator<SearchHit> hit_it = sr1.getHits().iterator();
	
            while(hit_it.hasNext()){
	
                boolean foundName = false;
                SearchHit hit = hit_it.next();
	
                Map<String,Object> result = hit.getSourceAsMap()
	
                HashMap<String, String> entry = new HashMap<>();
	
                for(DataSourceAttribute dsAttr:ds.attributes){
					if(!dsAttr.importAttr){ // don't include attr those are not marked for import
						continue
					}
					def val = ElasticSearchUtils.getValue(result, dsAttr)
                    String attr = dsAttr.originFieldName
					if((attr == "op_merge_merged_record_ids" || attr == "op_merge_updated_related_ids") && val?.length()>esLim){
						// es field limit is 32766 char
						String valLimited = val.substring(0,esLim);
						String valAppended = valLimited + "...additional characters were truncated";
						entry.put(attr, valAppended);
					}else{
						entry.put(attr, val);
					}

					entry.put("@id", hit.getId())
					entry.put("@index", hit.getIndex())
                }
	
                //entry.put("message", message);
                list.add(entry)
            }
			
			if(searchAggregation !=null){
				for (Map searchAgg : searchAggregation) {
					List<String> aggTypeList = (List)searchAgg.get("type");

					String dsAttrName = (String)searchAgg.get("field");
					for(String aggType:aggTypeList){
						String key = dsAttrName.replaceAll("[^A-Za-z0-9]","_") + "---" +aggType
						Map attrAggValMap
						if(aggValues.containsKey(dsAttrName)){
							attrAggValMap = aggValues.get(dsAttrName)
						}
						else{
							attrAggValMap =  new HashMap();
							aggValues.put(dsAttrName, attrAggValMap)
						}
						switch (aggType){
							case "sum":
								Sum sumV = sr1.getAggregations().get(key);
								if(!Double.isInfinite(sumV.getValue()) && !Double.isNaN(sumV.getValue())){
									attrAggValMap.put(aggType, sumV.getValue())
								}
								else{
									attrAggValMap.put(aggType,null)
								}
								break;
							case "min":
								Min minV = sr1.getAggregations().get(key);
								if(!Double.isInfinite(minV.getValue()) && !Double.isNaN(minV.getValue())){
									attrAggValMap.put(aggType, minV.getValue())
								}
								else{
									attrAggValMap.put(aggType,null)
								}
								break;
							case "max":
								Max maxV = sr1.getAggregations().get(key);
								if(!Double.isInfinite(maxV.getValue()) && !Double.isNaN(maxV.getValue())){
									attrAggValMap.put(aggType, maxV.getValue())
								}
								else{
									attrAggValMap.put(aggType,null)
								}
								break;
							case "average":
								Avg avgV = sr1.getAggregations().get(key);
								if(!Double.isInfinite(avgV.getValue()) && !Double.isNaN(avgV.getValue())){
									attrAggValMap.put(aggType, avgV.getValue())
								}
								else{
									attrAggValMap.put(aggType,null)
								}
								break
							case "range":
								double minV = sr1.getAggregations().get(key).getMin();
								double maxV = sr1.getAggregations().get(key).getMax();
								
								if(!Double.isInfinite(minV) && !Double.isNaN(minV) &&
									!Double.isInfinite(maxV) && !Double.isNaN(maxV)) {
									attrAggValMap.put(aggType, (maxV-minV))
								}
								else{
									attrAggValMap.put(aggType, null)
								}
								
								break
							case "std_deviation":
								double stdV = sr1.getAggregations().get(key).getStdDeviation()
								if(!Double.isInfinite(stdV) && !Double.isNaN(stdV)){
									attrAggValMap.put(aggType, stdV)
								}
								else{
									attrAggValMap.put(aggType,null)
								}
								break
							case "null_count":
								Sum sumV = sr1.getAggregations().get(key);
								if(!Double.isInfinite(sumV.getValue()) && !Double.isNaN(sumV.getValue())){
									attrAggValMap.put(aggType, sumV.getValue())
								}
								else{
									attrAggValMap.put(aggType,null)
								}
								break;
							case "non_null_count":
								Sum sumV = sr1.getAggregations().get(key);
								if(!Double.isInfinite(sumV.getValue()) && !Double.isNaN(sumV.getValue())){
									attrAggValMap.put(aggType, sumV.getValue())
								}
								else{
									attrAggValMap.put(aggType,null)
								}
								break;
							case "mode":
								Terms terms = sr1.getAggregations().get(key);
								Collection<Terms.Bucket> buckets = terms.getBuckets();
								if(buckets.size() >0){
									attrAggValMap.put(aggType,buckets.get(0).getKey())
								}
								else{
									attrAggValMap.put(aggType,null)
								}
								break;
							case "cardinality":
								Cardinality cardinalityV = sr1.getAggregations().get(key);
								if(!Double.isInfinite(cardinalityV.getValue()) && !Double.isNaN(cardinalityV.getValue())){
									attrAggValMap.put(aggType, cardinalityV.getValue())
								}
								else{
									attrAggValMap.put(aggType,null)
								}
								break;
							default:
								break;
						}
					}
		
				}
			}
        }catch(e){
			log.error "Failed to search elasticsearch data. Error: ${e.getMessage()}",e
			return renderErrorResponse(500, "SEARCH_FAILED", e.getMessage())
		}

		//searchSourceBuilder.set
		String elQuery = searchSourceBuilder.toString()
		JSONObject qryJSON = JSON.parse(elQuery)
		elQuery = qryJSON.get("query").toString()
		log.debug "EL Query for Search: " + elQuery

        render (["data":list,"aggregations":aggValues, total: totalRecordsCount] as JSON)

    }
	
	 def dataSourceStats(){
		 if(!isUserAuthorized()) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 def id = params.EventDataSourceId ? params.EventDataSourceId : -1
		 def ds = EventDataSource.read(id as long)
		 // get number of data sets using the data source
		 
		 def publishedNames = ''
		 def unpublishedNames = ''
		 def publishedList = Service.findAllByStatusAndLogDataSource('published', ds)
		 def unpublishedList = Service.findAllByStatusAndLogDataSource('unpublished', ds)
		 
		 publishedList.each{
			 publishedNames += ', ' + it.name
		 }
		 if(publishedNames) publishedNames = publishedNames.substring(2)
		 
		 unpublishedList.each{
			 unpublishedNames += ', ' + it.name
		 }
		 if(unpublishedNames) unpublishedNames = unpublishedNames.substring(2)

		 
		 // get the number of pipelines using the data source
		 def jobList = eventDataSourceService.getDatasourceDependentJobs(ds)

		 def wkflws = eventDataSourceService.getDatasourceWorkflows(ds.id, null)
		 String wkFlWNames=""
		 if(wkflws){
			 wkflws.each{
				 if(wkFlWNames){
					 wkFlWNames += ", " +it.name
				 }
				 else{
					 wkFlWNames=it.name
					 
				 }
			 }
		 }

		 // Get datasource associated apps
		 def apps = appFactoryService.getEntityAssociatedApps([id.toString()], EntityType.EventDataSource)
		 def appNames = ""
		 if (apps?.appNames) {
			 apps.appNames.each {
				 if (appNames) {
					 appNames += ", " + it
				 } else {
					 appNames = it

				 }
			 }
		 }

		 // datasource used as refDS in jobs
		def asRefDsInJobsList = eventDataSourceService.checkDsUsedAsRefDsInJobs(ds)

		 respond published:publishedList.size(), publishedNames:publishedNames,
		 		 unpublished:unpublishedList.size(), unpublishedNames:unpublishedNames,
				 pipelines:jobList?.size(), pipelineNames:jobList?.join(", "), workflows:wkflws?wkflws.size():0,
				 workflowNames:wkFlWNames, asRefDsInJobsNum:asRefDsInJobsList.size(),
				 asRefDsInJobNames:asRefDsInJobsList.join(", "),
				  apps : apps.totalCount, appNames : appNames
	 }
	 
	 def dataSourceNameAvailStatus(){
		 if(!isUserAuthorized()) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 def tenantName = tenantService.userTenant
		 def name = params.name
		 def es = EventDataSource.createCriteria()
		 boolean status = false
		 
		 def results = es.list(params) {
			eq("tenantName", tenantName)
 			eq("name",name)	
		 }
		 if(results.totalCount == 0)
		 	status = true
		 render status
	 }

	 def searchEventDataHistoGram(){
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		
		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant
		def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		def props = getParametersToBind()
		RoleOrder userRole = user.role.authority as RoleOrder
		
		EventDataSource ds = EventDataSource.get(id)
		if(ds==null){
			render(status: 400, errors: 'CreationFailed') as JSON
			return
		}
		if(userRole.value < RoleOrder.ROLE_MANAGER.value || 
			(ds.tenantName != tenantName && !isUserSuperAdmin())
			) {
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}
		 String interval = params.interval
 
		 
		 DateHistogramInterval intervalVal = DateHistogramInterval.DAY
		 
		 if(interval.equalsIgnoreCase("Day")){
			 intervalVal = DateHistogramInterval.DAY
		 }
		 if(interval.equalsIgnoreCase("Hour")){
			 intervalVal = DateHistogramInterval.HOUR
		 }
		 
		 if(interval.equalsIgnoreCase("Minute")){
			 intervalVal = DateHistogramInterval.MINUTE
		 }
		 if(interval.equalsIgnoreCase("Month")){
			 intervalVal = DateHistogramInterval.MONTH
		 }
		 if(interval.equalsIgnoreCase("Year")){
			 intervalVal = DateHistogramInterval.YEAR
		 }
		 if(interval.equalsIgnoreCase("Second")){
			 intervalVal = DateHistogramInterval.SECOND
		 }

		 SearchSourceBuilder searchSourceBuilder =  dataProcessingService.getELQueryObj(ds, props.toString(), null, null, null, user)
		 

		 List list = new ArrayList<>();
 
 
		 String indexTosearch = ds.indexAndTemplatePrefix + "*"
		 try{
			 
			 AbstractAggregationBuilder dateAgg = AggregationBuilders.dateHistogram("stat1")
				 														.field("@timestamp")
			 															.dateHistogramInterval(intervalVal)

			 SearchResponse sr1 = ELKService.searchELData(searchSourceBuilder,[dateAgg], 0, null, ds)
			 
	 
			 if(sr1.getAggregations() !=null){
				 Histogram buckets = sr1.getAggregations().get("stat1")
				 for (Histogram.Bucket bucket : buckets.getBuckets()) {
					 HashMap<String, String> entry = new HashMap<>();
					 String date = bucket.getKey();
					 long total = bucket.getDocCount();
					 entry.put("date", date)
					 entry.put("count", total)
					 list.add(entry)
				 }
			 }
 
		 }
		 finally{
		 }
		 render list as JSON
 
	 }
	 
	def getInputRule(){

		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}

		def id = params.EventDataSourceId ? params.EventDataSourceId : -1
		
		def ds = EventDataSource.findByIdAndStatusNotEqual(id as long, "Deleted")
		if(!ds) {
			render(status: 404, errors: 'Not Found') as JSON
			return
		}

		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant

		RoleOrder userRole = user.role.authority as RoleOrder

		if(tenantName != ds.tenantName && userRole.value != RoleOrder.ROLE_OPENPRISE_ADMIN.value){
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}

		def retVal = [:]
		
		if(ds.isDataStore){
			def dpRule = dataPipelineService.getParentRuleAndPipeline(ds)
			retVal["rule"] = dpRule.get("rule")
			retVal["pipelineName"] = dpRule.get("pipeline")
		}

		
		render retVal as JSON
	}
	 
	 /*
	 def sendSearchDataToDownload(){
		 if(!isUserAuthorized()) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 
		 User user = tenantService.currentUser
		 def tenantName = tenantService.userTenant
		 def props = getParametersToBind()
		 Gson gson = new Gson()
 
	
		 def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		 
		 RoleOrder userRole = user.role.authority as RoleOrder
		 // users can only see data sources if he is an Admin or above
		 if(userRole.value < RoleOrder.ROLE_MANAGER.value) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return
		 }
		 
		 EventDataSource ds = EventDataSource.get(id)
		 if(ds.tenantName != tenantName) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return;
		 }		 
		 if(!eventDataSourceService.prepareDataToDownloadUpdated(props , id , null , user)){
			 render(status: 503, errors: 'service not available') as JSON
			 return;
		 }
		 render "SUCCESS"
	 
	 }
	 */

	def sendSearchDataToDownload(){
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}

		User user = tenantService.currentUser
		def tenantName = tenantService.userTenant
		def props = getParametersToBind()
		Gson gson = new Gson()


		def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1

		RoleOrder userRole = user.role.authority as RoleOrder
		// users can only see data sources if he is an Admin or above
		if(userRole.value < RoleOrder.ROLE_MANAGER.value) {
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}

		EventDataSource ds = EventDataSource.get(id)
		if(ds.tenantName != tenantName) {
			render(status: 403, errors: 'Forbidden') as JSON
			return;
		}
//		if(!eventDataSourceService.prepareDataToDownloadUpdated(props , id , null , user)){
//			render(status: 503, errors: 'service not available') as JSON
//			return;
//		}
//		render "SUCCESS"
		def maxtries= 2
		def retrycount=0
		def success = false
		while(retrycount<maxtries && !success){
			if(eventDataSourceService.prepareDataToDownloadUpdated(props,id,null,user)){
				success = true
			}
			else{
			// here we are waiting for 15 seconds
				TimeUnit.SECONDS.sleep(15)
				retrycount++
			}
		}
		if(success){
			render "SUCCESS"
		}
		else{
			render(status:503, errors:'Service not available') as JSON
		}

	}


	 def purgeData(){
		 if(!isUserAuthorized()) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 
		 def user = tenantService.currentUser
		 def tenantName = tenantService.userTenant
		 def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		 
		 RoleOrder userRole = user.role.authority as RoleOrder
		 
		 EventDataSource ds = EventDataSource.get(id)
		 if(ds == null){
			 render(status: 404, text: 'Missing or not a valid data source') as JSON
			 return
		 }
		 if (ds.dataFormat == 'SYSTEM') {
			 return renderErrorResponse(403, 'Cannot purge system data source')
		 }
		 if(ds.isDataStore){
			 render(status: 403, text: 'Can not delete '+TerminologyUtils.RULE+' output data sources') as JSON
			 return
		 }
		 if(ds.tenantName != tenantName || userRole.value < RoleOrder.ROLE_ADMIN.value) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return
		 }
		 
		 def retVal = ["status": 200, "message":"SUCCESS"]
		 if(request.JSON){
			 def props = getParametersToBind()
			 SearchSourceBuilder searchSourceBuilder = dataProcessingService.getELQueryObj(ds, props.toString(), null, null, null, user)
			 // Calling this as opposed to purge because we don't want to delete down stream pipeline data
			 eventDataSourceService.deleteDataSourceData(ds, searchSourceBuilder , user)
		 }
		 else{
			 retVal = eventDataSourceService.purgeDataSource(ds , user)
		 }
		 if(retVal){
			 if(retVal?.get("status")){
				 response.status = retVal.get("status")
			 }
			 render retVal as JSON
		 }

	 }

	 def checkDependentJobsBeforePurge(){
		 if(!isUserAuthorized()) {
			 renderErrorResponse(401, 'Unauthorized' )
			 return
		 }

		 def user = tenantService.currentUser
		 def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1

		 RoleOrder userRole = user.role.authority as RoleOrder

		 EventDataSource ds = EventDataSource.get(id)
		 if(ds == null || ds.status == "Deleted"){
			 renderNotFoundErrorResponse('Datasource')
			 return
		 }
		 if(ds.isDataStore){
			 renderErrorResponse(403,'Can not delete' +TerminologyUtils.RULE+ 'output data sources')
			 return
		 }
		 def userIsAdmin = Administrators.isUserAdmin(user, ds)
		 if(!userIsAdmin) {
			 renderErrorResponse(403, 'Forbidden')
			 return
		 }
		 def retVal = eventDataSourceService.checkDependentJobsBeforePurge(ds)
		 response.status = retVal.get("status")
		 render retVal as JSON

	 }
	 	 
	 def addRecords(){
		 def user = tenantService.currentUser
		 def tenantName = tenantService.userTenant
		 
		 if(!user) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 
		 def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		 
		 EventDataSource ds = EventDataSource.get(id)
		 
		 if(!ds) {
			 render(status: 404, errors: 'Missing or not a valid data source.')  as JSON
			 return
		 }
		 
		 def userIsAdmin = Administrators.isUserAdmin(user, ds)
		 if(!userIsAdmin) {
			 userIsAdmin = ds.dataSourceAdmin.id == user.id
		 }
		 if(!userIsAdmin || ds.tenantName != tenantName) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return;
		 }
		 def props = JSON.parse(request)
		 props.remove('tenantName')
		 props.remove('importInfo')
		 Gson gson = new Gson()
		 List<HashMap> data = gson.fromJson(props.toString(), ArrayList.class);
		 if(!dataSourceCRUDService.addRecords(id, data)){
			  render(status: 404, errors: 'Missing required field value')  as JSON
			 return;
		 }
		 eventDataSourceService.saveLastUpdatedInfo(ds, "Manual")
		 render "SUCCESS"
	 }
	 
	 def updateRecords(){
		 def user = tenantService.currentUser
		 def tenantName = tenantService.userTenant
		 
		 if(!user) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 
		 def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		 
		 EventDataSource ds = EventDataSource.get(id)
		 
		 if(!ds) {
			 render(status: 404, errors: 'Missing or not a valid data source.')  as JSON
			 return
		 }
		 
		 def userIsAdmin = Administrators.isUserAdmin(user, ds)
		 if(!userIsAdmin) {
			 userIsAdmin = ds.dataSourceAdmin.id == user.id
		 }
		 if(!userIsAdmin || ds.tenantName != tenantName) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return;
		 }
		 def props = JSON.parse(request)
		 props.remove('tenantName')
		 props.remove('importInfo')
		 Gson gson = new Gson()
		 List<HashMap> data = gson.fromJson(props.toString(), ArrayList.class);
		 if(!dataSourceCRUDService.updateRecords(id, data)){
			 render(status: 404, errors: 'Missing required field value')  as JSON
			 return;
		 }
		 eventDataSourceService.saveLastUpdatedInfo(ds, "Manual")
		 render "SUCCESS"
	 }
	 
	 def deleteRecords(){
		 def user = tenantService.currentUser
		 def tenantName = tenantService.userTenant
		 
		 if(!user) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 
		 def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		 
		 EventDataSource ds = EventDataSource.get(id)
		 
		 if(!ds) {
			 render(status: 404, errors: 'Missing or not a valid data source.')  as JSON
			 return
		 }
		 
		 def userIsAdmin = Administrators.isUserAdmin(user, ds)
		 if(!userIsAdmin) {
			 userIsAdmin = ds.dataSourceAdmin.id == user.id
		 }
		 
		 if(!userIsAdmin || ds.tenantName != tenantName) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return;
		 }
		 def props = JSON.parse(request)
		 props.remove('tenantName')
		 props.remove('importInfo')
		 Gson gson = new Gson()
		 List<HashMap> data = gson.fromJson(props.toString(), ArrayList.class);		 
		 dataSourceCRUDService.deleteRecords(id, data)
		 eventDataSourceService.saveLastUpdatedInfo(ds, "Manual")
		 render "SUCCESS"
	 }
	 
	 def getDataStatistics() {
		 def reqDeleted = params.reqDeleted?.toBoolean()?:false
		 def dsID = params.EventDataSourceId.toLong()
		 def ds = EventDataSource.get(dsID)
		 
		 def user = tenantService.currentUser
		 if(!user) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 
		 def stats = dataSourceCRUDService.getDataStatistics(ds, reqDeleted)
		 respond stats
	 }
	 
	 def isAutoSearchAvailable(){
		 if(!isUserAuthorized()) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 def dsID = params.EventDataSourceId.toLong()
		 EventDataSource ds = EventDataSource.get(dsID)
		 def tenantName = tenantService.userTenant
		 def user = tenantService.currentUser
		 if(ds && ds.tenantName != tenantName && !isUserSuperAdmin()) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return
		 }else if(!ds || ds.status == 'Deleted'){
			 render(status: 404, errors: 'Data source not found') as JSON
			return
		 }
		 def stats = ELKService.getDocCountInAnIndex(ds) as Long
		 def dsAutoSearchCapRecordCount = Configuration.findByNameAndType("dsAutoSearchCapRecordCount", "system")?.value?.toLong()?:0
		 def retVal = ["isAutoSearchAvailable" : stats <= dsAutoSearchCapRecordCount , "recordCount" : stats]
		 render retVal as JSON
	 }
	 
	 def sendArchiveDataToDownload(){

		 if(!isUserAuthorized()) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 
		 def user = tenantService.currentUser
		 def tenantName = tenantService.userTenant
		 
		 def props = getParametersToBind()
		 def dsID = params.EventDataSourceId ?: -1
		 			 		 	 
		 EventDataSource ds = EventDataSource.get(dsID as long)
		 if(ds && ds.tenantName != tenantName) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return
		 }else if(!ds || ds.status == 'Deleted'){
		 	render(status: 404, errors: 'Data source not found') as JSON
			return
		 }
		 
		 RoleOrder userRole = user.role.authority as RoleOrder
		 // users can only see data sources if he is an Admin or above
		 if(userRole.value < RoleOrder.ROLE_MANAGER.value) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return
		 }
		 
		 String filesToDownload = props.filesToDownload ?: null
		 String fileFormatType = props.fileFormat 
		 
		 if(!fileFormatType || (fileFormatType && !["CSV","EXCEL"].contains(fileFormatType.toUpperCase()))){
			 fileFormatType = "CSV"
		 }
		 
		 String downloadDescription = props.description ?: null
		 
		 if(downloadDescription == null || filesToDownload == null){
			 render(status: 400, errors: 'Bad Request') as JSON
			 return
		 }
		 
		 def downloadList = []
		 BoolQueryBuilder filter = QueryBuilders.boolQuery()
		 filter.should(QueryBuilders.matchAllQuery())
		 
		 if(filesToDownload.equalsIgnoreCase("all")){
			 def availArchiveTypes = snapshotService.getAvailArchiveTypesByUser(user)
			 def availableArchives = snapshotService.getListOfAvailArchives(ds, availArchiveTypes)
			 for(def archive in availableArchives){
				// Cannot download 'FAILED' archives
				if(archive.status == "FAILED") continue
				
				def file = [:]
				file.put("id", archive.archiveID)
				file.put("index", archive.elkIndexName)
				file.put("type", archive.elkType)
				file.put("filter", filter)
				file.put("targetFileName", archive.name)
				file.put("isNew", archive.isNew)

				downloadList << file
			}
		 }else{
			 def file = [:]			
			 file.put("id", filesToDownload)
			 file.put("index", "archive_" + ds.indexAndTemplatePrefix + "_" + filesToDownload)
			 file.put("type", "Archive_" + ds.mappingName)
			 file.put("filter", filter)		
			 
			 def targetFileName = null
			 try{
				 def createAt = new Date().parse("MMddyyy", filesToDownload).format("MMM-dd-yyyy")
				 targetFileName = ds.name + "_" + createAt
				 file.put("isNew", false)
			 }catch(Exception e){
				 file.put("type", ds.mappingName)
				 targetFileName = ds.name
				 file.put("isNew", true)
			 }
			 file.put("targetFileName", targetFileName)
			 downloadList << file	 		
		 }
		 
		 if(downloadList){
			 String downloadLocation = Configuration.findByNameAndType("fileUploadRoot", "system").value + File.separator + tenantName + File.separator + "Archives"
			 Map downloadProps = new HashMap()
			 downloadProps.put("fileName", downloadDescription)
			 downloadProps.put("rootFolderLocation", downloadLocation)
			 snapshotService.downloadArchiveDataSource(downloadList, downloadProps, ds, fileFormatType, user)
		 }
		 
		 render "SUCCESS"
	 }
	 
	 def cloneDataSource(){
		 
		 if(!isUserAuthorized()) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 
		 def dsID  = params.EventDataSourceId ?: -1
		 def dataSource = EventDataSource.get(dsID)
		 def user = tenantService.currentUser
		 def tenantName = tenantService.userTenant
		 
		 if(!userAllowedAction("save", user, dataSource)) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return
		 }
		 
		 if(!dataSource || dataSource.status == "Deleted"){
			 render(status: 404, errors: 'Datasource not found') as JSON
			 return
		 }		 
		 
		 def props = getParametersToBind() 
		 def targetDSName = props.newDSName ?: "Clone of " + dataSource.name
		 def archiveID = props.archiveID ?: null
		 
		 if(!archiveID){
			 render(status: 400, errors: 'Bad Request') as JSON
			 return
		 }
		 
		 boolean status = snapshotService.restoreArchiveAsDataSource(dataSource, archiveID, targetDSName, user, tenantName)
		 
		 if(status){
			 render "SUCCESS"
		 }else{
			 render "FAILED"
		 }

	 }

	 def getDuplicateRecords(){
		 
		 if(!isUserAuthorized()) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 
		 def user = tenantService.currentUser
		 def tenantName = tenantService.userTenant
		 def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		 
		 RoleOrder userRole = user.role.authority as RoleOrder
		 
		 List list = new ArrayList<>();
		 
		 
		 EventDataSource ds = EventDataSource.get(id)
		 if(ds==null){
			 render(status: 400, errors: 'SearchDuplicateRecordsFailed') as JSON
			 return
		 }
		 // users can only see data sources if he is an Admin or above
		 if(userRole.value < RoleOrder.ROLE_MANAGER.value || ds.tenantName != tenantName) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return
		 }
		 
 
		 int page = Integer.parseInt(params.page)
		 int size = Integer.parseInt(params.size)
		 
		 def sortBy = params.sortBy
		 def sortOrd = params.sortOrder
		 
		 String sortDSAttr = "@timestamp"
		 SortOrder sortOrder = SortOrder.ASC
		 if(sortBy){
			  sortDSAttr = dataProcessingService.getDSAttribute(ds, sortBy)
			  String type = dataProcessingService.getDSAttributeType(ds, sortBy)
			  if(type.equalsIgnoreCase("string")){
				  sortDSAttr =sortDSAttr+RuleConstants.DS_ATTR_LOWERCASE_SUFFIX
			  }
		 }
			  
		  if(sortOrd){
			  if(sortOrd.equals("asc")){
				  sortOrder = SortOrder.ASC
			  }
			  else{
				  sortOrder = SortOrder.DESC
			  }
		  }
		  
		  SortBuilder sortBuilder = SortBuilders.fieldSort(sortDSAttr).order(sortOrder)
		  
		 
		 def dupeType = params.dupeType
		 
		 DataSourceAttribute duplicateAttr = DataSourceAttribute.findByDataSourceValAndOriginFieldName(ds, RuleConstants.DEDUPE_DUPE_ATTR)
		 
		 //If dupe attribute doesnt exist, return immediately 
		 if(duplicateAttr==null){
			 render (["data":list] as JSON)
			 return 
		 }
		 
		 def props = JSON.parse(request) ? getParametersToBind() : "{}"
		 BoolQueryBuilder qry = dataProcessingService.getBoolQuery(ds, props.toString(), null, null)
		 
		 def surviveRecID
		 List surviveList = new ArrayList()
		 
		 if(dupeType.equals("Non-surviving")){
			 surviveRecID = params.surviveRecID
			 surviveList.add(surviveRecID)
		 }
		 
		 int from  = (page-1)*size
 
		 long total=0
		 int itertations = 0
		 
		 String keyField = ds.keyField
		 
		 
			 
		 BoolQueryBuilder qry1
		 if(dupeType.equals("Surviving")){
			 qry1 = new BoolQueryBuilder().must(QueryBuilders.termsQuery(duplicateAttr.name, ["Surviving", "Surviving Merged"]));
		 }
		 else{
			 qry1 = new BoolQueryBuilder().must(QueryBuilders.termsQuery(OPRuleMarkerConstants.DEDUPE_SURVIVING_REC_ID, surviveList));
			 qry1 = qry1.must(QueryBuilders.termsQuery(duplicateAttr.name, ["Non-surviving", "Surviving Original"]));
		 }
		 
		 BoolQueryBuilder dupeQry = new BoolQueryBuilder().must(qry)
		 dupeQry = dupeQry.must(qry1)
		 

		 try{
			 
			 SearchResponse sr1 = ELKService.searchELData(dupeQry,[], size, ["from":from, "sort":sortBuilder], ds)
			 				 
			 java.util.Iterator<SearchHit> hit_it = sr1.getHits().iterator();
			 total = sr1.getHits().totalHits
			 if (sr1.getHits().hits.length > 0) {
				 while(hit_it.hasNext()){
		 
					 SearchHit hit = hit_it.next();
		 
					 Map<String,Object> result = hit.getSourceAsMap();
		 
					 HashMap<String, String> entry = new HashMap<>();
		 
					 for(DataSourceAttribute dsAttr:ds.attributes){
						 def val
						 if(dsAttr.esType!=null && dsAttr.esType.equals("nested")){
							 
							 val  = result.get(dsAttr.name)!=null?((String)(result.get(dsAttr.name).get("raw"))):null
						 }
						 else{
							 val  = result.get(dsAttr.name)
						 }
					 
						 String attr = dsAttr.originFieldName
						 
						 
						 entry.put(attr, val);
					 }
					 entry.put("@id", hit.getId())
					 entry.put("@index", hit.getIndex())
					 entry.put(OPRuleMarkerConstants.DEDUPE_SURVIVING_REC_ID, result.get(OPRuleMarkerConstants.DEDUPE_SURVIVING_REC_ID))
		 
					 //entry.put("message", message);
					 list.add(entry)
				 }
			 }
		 } 
		 finally{
		 }

		 render (["data":list, "total":total] as JSON)
		 
	 }
	 
	 def unmarkDupeRecord(){
		 def recordID = params.recordID
		 
		 if(!isUserAuthorized()) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 
		 def user = tenantService.currentUser
		 def tenantName = tenantService.userTenant
		 def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		 
		 RoleOrder userRole = user.role.authority as RoleOrder
		 
		 List list = new ArrayList<>();
		 
		 
		 EventDataSource ds = EventDataSource.get(id)
		 if(ds==null){
			 render(status: 400, errors: 'unmarkDupeRecordFailed') as JSON
			 return
		 }
		 // users can only see data sources if he is an Admin or above
		 if(userRole.value < RoleOrder.ROLE_MANAGER.value || ds.tenantName != tenantName) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return 
		}
		 
		eventDataSourceService.unMarkDupesInManaulReviewDS(ds, recordID)
		render([message: 'SUCCESS'] as JSON)
		 
	 }
	 
	 def runDataAssessmentReportNow() {
		 if(!isUserAuthorized()) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
 
		 def user = tenantService.currentUser
		 def tenantName = tenantService.userTenant
		 def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		 
		 EventDataSource ds = EventDataSource.get(id)
		 if(ds==null){
			 render(status: 404, errors: 'Not Found') as JSON
			 return
		 }
		 def userIsAdmin = eventDataSourceService.isUserDsAdmin(user, ds)
		 if(!userIsAdmin || ds.tenantName != tenantName) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return;
		 }
		 
		 ServiceResponse sp = ServiceResponse.successResponse()
		 if( !ds.dataAssessment || !ds.dataAssessment.shadowPipeline || ds.dataAssessment.shadowPipeline.status == "Deleted") {
			 // create shadowpipeline first
			 def props = getParametersToBind()
			 String shadowPipelineName = "SYS_DA_" + ds.name
			 sp = dataAssessmentService.saveAndRunShadowPipeline(ds, shadowPipelineName, props)
			 if(sp && !sp.isSuccess()) {
				 log.error("Shadow Pipeline ${shadowPipelineName} creation failed: ${sp}!")
				 render(status: sp.status, text: sp.message) as JSON
				 return
			 }
			 log.info("Shadow Pipeline ${shadowPipelineName} creation completed!")
		 }else { // if shadow pipeline is present, create workflow if it is not available
			 def shadowProcess = processService.createWorkflowFromPipeline(ds.dataAssessment.shadowPipeline , "Active")
			 log.info(" creation of workflow if not exist for data Assessment status" + shadowProcess.status + " and message :: " + shadowProcess?.message)
		 }
		 
		 if(sp.isSuccess() && eventDataSourceService.isEventDataSourceEmpty(ds))
		 {
			 sp = ServiceResponse.errorResponse("400", "Data assessment is empty.")
		 }
		 
		 if (sp.isSuccess() && ds.dataAssessment && ds.dataAssessment.shadowPipeline) {
			 log.info("Running Shadowpipeline now")
			 def daId = ds.dataAssessment.id
			 try {
				 DataAssessment da = ds.dataAssessment
				 def shadowPipelineId = da.shadowPipeline.id
				 log.info("Staring shadow pipeline for da: ${daId}, shadowpipeline: ${da.shadowPipeline.name}(${shadowPipelineId})...")
				 sp = dataPipelineService.runShadowPipelineNow(da.shadowPipeline)
				 
				 // set da to be initialized
				 if (da.isInitialized == false)
				 {
					 da.isInitialized = true
					 da.save(true)
				 }
			 } catch (Exception e) {
				 log.error(e.getLocalizedMessage(), e)
				 sp = ServiceResponse.internalError(e.getLocalizedMessage())
			 }
		 } else {
		     sp = ServiceResponse.errorResponse("400", "Data assessment is not ready yet, please try again later.")
		 }
 
		 if(sp.isSuccess()) {
			 render([message: 'SUCCESS'] as JSON)
		 } else {
			 render(status: sp.status, text: sp.message) as JSON
		 }
	 }
	 
	 def isDataAssessmentReportRunning(){
		 if(!isUserAuthorized()) {
			 render(status: 401, text: 'Unauthorized') as JSON
			 return
		 }
		 
		 def user = tenantService.currentUser
		 def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		 
		 EventDataSource ds = EventDataSource.get(id)
		 if(ds==null || ds.dataAssessment == null || ds.dataAssessment.shadowPipeline == null){
			 render(status: 404, text: 'Not Found') as JSON
			 return
		 }

		 def pipelineId = ds.dataAssessment.shadowPipeline.id
		 
		 DataPipeline pipeline = ds.dataAssessment.shadowPipeline
		 
		 // needs to be datasource admin 
		 if(!eventDataSourceService.isUserDsAdmin(user,  ds) || pipeline.status == 'Deleted' ) {
			 render(status: 403, text: 'Forbidden') as JSON
			 return
		 }
		 JobKey jobKey = new JobKey(pipeline.scheduleJobName)
		 
		 if(dataPipelineService.isRunning(pipelineId, pipeline.tenantName)){
			 render true
		 }
		 else{
			 render false
		 }
	 }
	 
	 def createDSWithAuthDetails(){
		 if(!isUserAuthorized()) {
			 render(status: 401, text: 'Unauthorized') as JSON
			 return
		 }
		 
		 
		 def tenantName = tenantService.userTenant
		 def user = tenantService.currentUser
		 RoleOrder userRole = user.role.authority as RoleOrder
		 
		 // users can only see data sources if he is an Manager or above
		 if(userRole.value < RoleOrder.ROLE_ADMIN.value) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return
		 }
		 
		 def providersMap = [salesforce : 'sforce', marketo : 'marketo', pardot : 'pardot',
			 gdrive_csv : 'gdrive', gdrive_sheet : 'gdrivesheets', desk : 'desk',
			 box : 'box', redshift : 'redshift']
		 def props = request.JSON
		 def provider = props.keySet().find{it != 'ds_details'}
		 def dsDetails = props.getAt("ds_details")
		 def authDetails = props.getAt(provider)		 
		 def providerKey = providersMap.getAt(provider)?:provider
		 
		 def oauthService = Oauth2Factory.availableInputProviders[providerKey]
		 
		 if(!oauthService || !dsDetails){
			 render(status: 400, errors: 'Bad Request') as JSON
			 return
		 }
		 		 
		 def providerObj = Oauth2Factory.getInstance(oauthService, [:])
		 def authInfo = providerObj.getAuthentication()	 
		 
		 def instance = null
		 def authProvider = null
		 def config = [:]
		 HashMap dsMap = []		 
		 
		 boolean isValidAuthentication = false
		 
		 // Check Authencation type Oauth2 / AuthMethod
		 if(authInfo.type == "oauth2"){

			 // Save Oauth2 authentication details 
			 authProvider = new Oauth2()
			 use (groovy.time.TimeCategory) {
				 authProvider.expiration  = 1.hour.from.now
			 }
			 authProvider.user = user
			 authProvider.tenantName = tenantName
			 authProvider.type = "storage"
			 authProvider.provider = providerKey
			 authDetails.each{
				 authProvider[it.key] = it.value
			 }
			 authProvider.save()
			 
			 // Get config details of the provider and create object
			 config = new Oauth2Controller().getConfigByProvider(authProvider,[:])
			 instance = Oauth2Factory.getInstance(oauthService, config)
			 
			 // Config required to test authentication 			 
			 def testConfig = ['access_token':authDetails.accessToken,'id':authDetails.userIdent]
			 isValidAuthentication = instance.validAuthentication(testConfig).valid
			 
			 // update Oauth2 with other info only if given auth details are valid
			 if(isValidAuthentication){				
				 // Get authenticated user identification details
				 def userIdentity = instance.getAuthUserIdentifier(testConfig)
				 authProvider.userIdentData = userIdentity?JsonOutput.toJson(userIdentity):''
				 // Get instance URL with authentication info	
				 authProvider.instanceUrl = providerObj.getInstanceUrl(config)
				 authProvider.save(flush:true,failOnError:true)
				 AuthService.changeAuthAndInvalidate(authProvider, [:])
				 dsMap.dataProvider = authProvider?.id
			 }
		 }else{
		 	
		 	// Prepare and save AuthMethod authentication details 
		 	authProvider = new AuthMethod()	 
			authProvider.tenantName = tenantName
			authProvider.user = user 
		 	def fieldValues = [] 
			authDetails.each{
				def auth = [:]
				auth << ['name':it.key]
				auth << ['value':it.value]
				fieldValues << auth
			}
			authProvider.fieldValues = JsonOutput.toJson(fieldValues)
			authProvider.save()
			
		 	config[Oauth2Provider.AUTH_VALUES] = authProvider.fieldValues
		 	instance = Oauth2Factory.getInstance(oauthService, config)

			// Check authentication 
			isValidAuthentication = instance.validAuthentication(null)?.valid
			if(isValidAuthentication){
				def userIdentity = instance.getAuthUserIdentifier(config)
				authProvider.userIdent = userIdentity.identity
				authProvider.userIdentData = userIdentity?JsonOutput.toJson(userIdentity):''
				authProvider.fields = authInfo.input?JsonOutput.toJson(authInfo.input):''
				authProvider.name =  authInfo.name
				authProvider.provider = providerKey
				authProvider = authProvider.save(flush:true)
				AuthService.changeAuthAndInvalidate(authProvider, [:])
				dsMap.authMethod = authProvider?.id
			}
		 }
				
		 if(!isValidAuthentication){
			 render(status: 400, errors: 'Invalid authentication details') as JSON
			 return
		 }	
		 	 
		 dsDetails.dpPath = dsDetails.objectType
		 def fieldInfo = instance.getProviderFieldsInfo(authDetails.accessToken, dsDetails.dpPath)
		 def entity = fieldInfo.entities?.find{it.name == dsDetails.dpPath}
		 def ds = null
		 
		 if(fieldInfo && entity){			 
			 dsMap.columnLine = fieldInfo.columnLine	
			 dsMap.dataRowNum = fieldInfo.dataRowNum			
			 dsMap.primaryDateSource = fieldInfo.primaryDateSource?:null			
			 dsMap.skipFooterNum = fieldInfo.skipFooterNum
			 dsMap.timeZoneName = fieldInfo.timezone
			 dsMap.timeZone = fieldInfo.timezone?.substring(1,10)
			 
			 // Setting key/timestamp/updateTimestamp fields from fieldInfo
			 dsMap.keyFieldLabel = fieldInfo.keyField
			 dsMap.timestampFieldLabel = fieldInfo.timestampField
			 dsMap.updateTimestampFieldLabel = fieldInfo.udpateTimestampField
			 
			 // Setting default values
			 dsMap.dataFormat = 'CSV'
			 dsMap.scheduleStatus = 'Disabled'
			 dsMap.dpUnit = "minutes"
			 dsMap.dpFrequency = "every"
			 dsMap.dpCheckFrequency = 15
			 
			 // Overriding ds details with user specified values 
			 dsDetails.each{
				 dsMap[it.key] = it.value
			 }
			 
			 // Override tenantName and user
			 dsMap.tenantName = tenantName
			 dsMap.dataSourceAdmin = user.id
			 
			 // Setting data source attributes
			 dsMap.attributes = []
			 entity.fields.eachWithIndex{ item, index ->
				 def attr = [:]
				 attr.originFieldName = item.name
				 attr.type = item.type
				 attr.importAttr = true
				 attr.unit = null
				 attr.fieldOrder = index+1
				 dsMap.attributes << attr
			 }
			 
			 try{
				 ds = eventDataSourceService.createDataSource(dsMap)
			 }catch(Exception e){
				 if(e.getMessage() !=null && e.getMessage().equals("NULL_OR_BLANK_ATTR_NAME")){
					 render(status: 400, errors: 'NULL_OR_BLANK_ATTR_NAME') as JSON
				 }else{
				 	 render(status: 400, errors: 'CreationFailed') as JSON
				 }								  				 
			 }
		 }
		 
		 if(ds == null){
			 // If DS failed to create then remove authentication details 			 
			 authProvider?.delete()
			 render(status: 400, errors: 'CreationFailed') as JSON
			 return
		 }
		 
		 postSave("save", ds)
 
		 render ds as JSON
	 }
	 
	 def addAttributes(){
		 if(!isUserAuthorized()) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 def user = tenantService.currentUser
		 def tenantName = tenantService.userTenant
		 def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		 
		 EventDataSource ds = EventDataSource.get(id)
		 if(ds==null){
			 render(status: 400, errors: 'addAttributes Failed') as JSON
			 return
		 }
		 
		 def userIsAdmin = Administrators.isUserAdmin(user, ds)
		 if(!userIsAdmin) {
			 userIsAdmin = ds.dataSourceAdmin.id == user.id
		 }
		 if(!userIsAdmin || ds.tenantName != tenantName) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return;
		 }
		 
		 def props = request.JSON
		 
		 Gson gson = new Gson()
		 
		 List attrs = gson.fromJson(props.toString(), ArrayList.class)
		 eventDataSourceService.updateDataSource(ds, attrs, null, null, null)
 
		 render "SUCCESS"
	 }

	/**
	 * To update System data source
	 * @return
	 */
	def updateSystemDataSource(){

		if(!isUserAuthorized()) {
			return renderErrorResponse(401, 'Unauthorized' )
		}

		if(!isUserSuperAdmin()) {
			return renderErrorResponse(403, 'Forbidden' )
		}

		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant
		def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1

		EventDataSource ds = EventDataSource.get(id)
		if(!ds || ds.status == "Deleted") {
			return renderNotFoundErrorResponse("Data Source")
		}

		if(!Administrators.isUserAdmin(user, ds)) {
			return renderErrorResponse(403,'Forbidden')
		}

		def props = request.JSON

		Map attrs = new JsonSlurper().parseText(props.toString())

		List attrsToAdd = []
		List attrsToDelete = []
		List typeChangedAttr = []
		List importChangedAttr = []

		if(attrs.attrsToAdd) {
			attrsToAdd = attrs.attrsToAdd
		}

		if(attrs.attrsToDelete) {
			attrsToDelete = attrs.attrsToDelete
		}

		if(attrs.typeChangedAttr) {
			typeChangedAttr = attrs.typeChangedAttr
		}

		if(attrs.importChangedAttr) {
			importChangedAttr = attrs.importChangedAttr
		}

		eventDataSourceService.updateSystemDataSource(ds, attrsToAdd, attrsToDelete, typeChangedAttr, importChangedAttr)

		render "SUCCESS"
	}

	 def getAllNonAutomatedDs(){
		 if(!isUserAuthorized()) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 String tenantNameFilterStr = null
		 if(params.tenantName && params.tenantName.toString().trim()){
			 if(!isUserSuperAdmin()){
				 render(status: 403, errors: 'TenantName Filter Forbidden') as JSON
				 return
			 }
			 tenantNameFilterStr = params.tenantName.toString().trim()
		 }
		 
		 def tenantName = tenantService.userTenant
		 def user = tenantService.currentUser
		 RoleOrder userRole = user.role.authority as RoleOrder
		 
		 // users can only see data sources if he is an Admin or above
		 if(userRole.value < RoleOrder.ROLE_ADMIN.value) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return
		 }
		 
		 def c
 
		 DataPipeline pipeline = params.pipelineId ? DataPipeline.get(params.pipelineId) : null
		 def results = []

		 def leadToCircularDsIds = []
		 if(pipeline){
		 	leadToCircularDsIds = dataPipelineService.dependentPipeline(pipeline.id)
		 }
		 c = EventDataSource.createCriteria()
		 results = c.list() {
			 ne("status", "Deleted")
			 ne("status", "Hidden")
			 eq("tenantName", tenantName)
			 eq("visibility", "User")
			 if(leadToCircularDsIds) not {'in'("id",leadToCircularDsIds)}
			 order("name", "asc")
		  }
		 def retval = []
		
		 results.each{
				 def item = [:]
				 item.id = it.id
				 item.name = it.name
				 item.dpPath = it.dpPath
				 item.description = it.description
				 item.importInfo = it.importInfo
				 item.isDataStore = it.isDataStore
				 item.scheduleStatus = it.scheduleStatus
				 item.isAdmin = false //(it.dataSourceAdmin.id == user.id ? true : false)
				 item.allowManualUpdate = it.allowManualUpdate
				 item.daysToArchive = it.daysToArchive
				 item.dataAssessment = it.dataAssessment
				 if(!item.isAdmin) {
					 item.isAdmin = Administrators.isUserAdmin(user, it)
				 }
				 
				 if(it.dataProvider) {
					 def provider = Oauth2.load(it.dataProvider.id)
					 item.oauth = [:]
					 item.oauth.id = provider.id
					 item.oauth.provider = provider.provider
					 item.oauth.isValid = provider.isValid
				 }
				 
				 if(it.authMethod) {
					 def provider = AuthMethod.load(it.authMethod.id)
					 item.authMethod = [:]
					 item.authMethod.id = provider.id
					 item.authMethod.provider = provider.provider
					 item.authMethod.isValid = provider.isValid
				 }				 
				 retval.push(item)
		 }
		 render retval as JSON
		 
	 }

	 
	 def runArchiveDataSourcesJob() {
		 if(!isUserAuthorized()) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		  
		 def user = tenantService.currentUser
		 if(user.role.authority != "ROLE_OPENPRISE_ADMIN"){
			 render(status: 403, errors: 'Forbidden') as JSON
			 return
		 }
				  
		 JobKey jobKey = new JobKey("Openprise system archive datasources Job")
		 if(OPQuartzSchedulerService.isJobRunning(jobKey.name, jobKey.group, tenantService.getSuperTenant())){
			 response.status = 409
			 render([error: 'Conflict'] as JSON)
			 return
		 }
		 OPQuartzSchedulerService.triggerJob(jobKey.name, tenantService.getSuperTenant())
		 
		 render "SUCCESS"
	 }
	 

	 def assessmentReport() {
		 if(!isUserAuthorized()) {
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 
		def tenantName = tenantService.userTenant
		def id = params.id.isNumber() ? params.id : -1
		def ds = EventDataSource.get(id)
	
		def user = tenantService.currentUser
		RoleOrder userRole = user.role.authority as RoleOrder
		 
		if(ds && ds.tenantName != tenantName || userRole.value < RoleOrder.ROLE_MANAGER.value) {
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}
		
		if(!ds || ds.status == "Deleted"){
			render(status: 404, errors: 'Data source not found') as JSON
			return
		}
		 
		 def folderName = null
		 def entity = ds.dpPath
		 entity = entity?.replaceAll("\\s","") // remove all whitespaces because directory name can not have spaces 
		 def provider = ds.dataProvider?.provider?:ds.authMethod.provider

		 def oauthService = Oauth2Factory.availableInputProviders[provider]
		 if(!oauthService)
			 oauthService = Oauth2Factory.availableOutputProviders[provider]

		 if(oauthService) {
			 Oauth2Provider instance = Oauth2Factory.getInstance(oauthService, [:])
			 folderName = AssessmentUtils.assessmentFolderName[instance.getProviderId()]
			 def fileLoc = Configuration.findByNameAndType("fileUploadRoot", "system").value + File.separator + tenantName + File.separator + "Reports" + File.separator + folderName + File.separator + entity + File.separator + "Assessment_Report_${params.id}.html"
			 def htmlContent = new File(fileLoc).text
			 render text: htmlContent, contentType:"text/html", encoding:"UTF-8"
		 }
	 }

	 def getDsImportStatus(){
		 if(!isUserAuthorized()){
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 if(!isUserDataAdminOrHigher()) {
			 render(status: 403, errors: 'Forbidden') as JSON
			 return;
		 }
		 def props = getParametersToBind()
		 
		 List dsIds = props.dsId?.collect{if(it > 0) return it.toLong()}
		 
		 def retVal = eventDataSourceService.getImportStatus(dsIds)
		 if(retVal.containsKey("statusCode") && retVal.get("statusCode") == 503){
			render(status: retVal.get("statusCode"), errors: retVal.get("error")) as JSON
			return
		 }
		 
		 render  retVal as JSON
	 }

	def updateDsAttributes(){
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		def id = params.EventDataSourceId ? params.EventDataSourceId.toLong() : -1
		if (eventDataSourceService.isDsImporting(id)) {
			def details = [:]
			details << ['error_details': 'This data source is currently importing and changes cannot be saved. Please stop import and ensure the import process is stopped before saving the changes.']
			details << ['error_code': ErrorCodes.FAILED_TO_UPDATE_DATASOURCE]
			return renderErrorResponse(409, 'This data source is currently importing and changes cannot be saved. Please stop import and ensure the import process is stopped before saving the changes.', details)
		}

		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant

		EventDataSource ds = EventDataSource.get(id)
		if(ds==null){
			render(status: 400, errors: 'addAttributes Failed') as JSON
			return
		}

		def userIsAdmin = Administrators.isUserAdmin(user, ds)
		if(!userIsAdmin) {
			userIsAdmin = ds.dataSourceAdmin.id == user.id
		}
		if(!userIsAdmin || ds.tenantName != tenantName) {
			render(status: 403, errors: 'Forbidden') as JSON
			return;
		}

		def props = request.JSON

		Gson gson = new Gson()

		List attrs = gson.fromJson(props.toString(), ArrayList.class)
		eventDataSourceService.updateDsAttribute(ds, attrs)

		render "SUCCESS"
	}

	def getDsSize(){
		 if(!isUserAuthorized()){
			 render(status: 401, errors: 'Unauthorized') as JSON
			 return
		 }
		 def props = getParametersToBind()
		 List dsIds = props.dsId as List
		 def retVal = eventDataSourceService.getSize(dsIds)
		 render  retVal as JSON
	 }

	def getKeyFields(){
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}

		def tenantName = tenantService.userTenant
		def id = params.inputId ? params.inputId.toLong() : -1
		def type = params.inputType?:"datasource"

		def ds = null
		if(type.equals("datasource")) {
			ds = EventDataSource.get(id)
		}else if(type.equals("dataset")){
			ds = Service.get(id)
		}

		if(!ds || ds.status == "Deleted"){
			render(status: 404, errors: 'Datasource not found') as JSON
			return
		}

		if(!isUserSuperAdmin() && ds.tenantName != tenantName) {
			if(ds instanceof EventDataSource){
				render(status: 403, errors: 'Forbidden') as JSON
				return
			}else if(ds.accessType != "Public"){
				render(status: 403, errors: 'Forbidden') as JSON
				return
			}
		}

		render eventDataSourceService.getKeyFields(ds) as JSON

	}

	protected def isSuperAdminAndSystemObject(DataPipeline p) {
        return p && isUserSuperAdmin() && p.visibility.equalsIgnoreCase("System")
    }

	@Override
	protected boolean checkRequestDataAuthorization(Map myParams) {
		super.checkRequestDataAuthorization(myParams)
		if(myParams.containsKey("dataSourceAdmin")){
			checkAuthorizionForUserEntity(myParams, "dataSourceAdmin")
		}
		return true
	}

	def getdatasourceAssociatedJobs(){
		if(!isUserAuthorized()) {
			return renderErrorResponse(401, 'Unauthorized')
		}
		def id = params.EventDataSourceId ? params.EventDataSourceId : -1
		def ds = EventDataSource.read(id as long)

		if(!ds || ds.status == "Deleted"){
			return renderNotFoundErrorResponse('Datasource')
		}

		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant

		def userIsAdmin = Administrators.isUserAdmin(user, ds)
		if(!userIsAdmin || ds.tenantName != tenantName) {
			return renderErrorResponse(403, 'Forbidden')
		}
		def pipelineDetails = eventDataSourceService.getdatasourceAssociatedJobs(ds)
		respond total: pipelineDetails.size(), data : pipelineDetails
	}

	def addAttributesToDataSourceAssociatedjobs(){

		if(!isUserAuthorized()) {
			return renderErrorResponse(401, 'Unauthorized' )
		}
		def id = params.EventDataSourceId ? params.EventDataSourceId : -1
		def ds = EventDataSource.get(id as long)

		if(!ds || ds.status == "Deleted"){
			return renderNotFoundErrorResponse('Datasource')
		}

		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant

		def userIsAdmin = Administrators.isUserAdmin(user, ds)
		if(!userIsAdmin || ds.tenantName != tenantName) {
			return renderErrorResponse(403, 'Forbidden')
		}
		def props = request.JSON

		def jsonSlurper = new JsonSlurper()
		def attrsMap = jsonSlurper.parseText(props.toString())

		def attrs = attrsMap.get("attributes")
		attrs.each { attr ->
			if (!attr.importAttr) return renderErrorResponse(400, 'Bad Request')
		}
		def respMap = eventDataSourceService.addAttributesToDataSourceAssociatedjobs(ds, attrsMap)
		render respMap as JSON

	}

	def abortDsImport(){

		if(!isUserAuthorized()) {
			return renderErrorResponse(401, 'Unauthorized')
		}
		def id = params.EventDataSourceId ? params.EventDataSourceId : -1
		def ds = EventDataSource.read(id as long)

		if(!ds || ds.status == "Deleted"){
			return renderNotFoundErrorResponse('Datasource')
		}

		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant

		def userIsAdmin = Administrators.isUserAdmin(user, ds)
		if(!userIsAdmin || ds.tenantName != tenantName) {
			return renderErrorResponse(403, 'Forbidden')
		}
		def resp = eventDataSourceService.abortDsImport(id)
		render resp as JSON

	}

	/**
	 * API get additional attributes from the parent datasource
	 * Additional attributes : Attributes which are not marked for import
	 * and also which are not configured in DS but detected
	 * while importing data from CSV/Excel files
	 */
	def getAdditionalAttributes(){
		if(!isUserAuthorized()) {
			return renderErrorResponse(401, 'Unauthorized' )
		}
		def id = params.EventDataSourceId ? params.EventDataSourceId : -1
		def ds = EventDataSource.get(id as long)

		if(!ds || ds.status == "Deleted"){
			return renderNotFoundErrorResponse('Datasource')
		}

		def user = tenantService.currentUser
		def tenantName = tenantService.userTenant

		def userIsAdmin = Administrators.isUserAdmin(user, ds)
		if(!userIsAdmin || ds.tenantName != tenantName) {
			return renderErrorResponse(403, 'Forbidden')
		}

		def retVal = eventDataSourceService.getAdditionalAttributes(ds.id)

		render retVal as JSON
	}

	def checkImportAnomalyNow(){
		if(!isUserAuthorized()) {
			return renderErrorResponse(401, 'Unauthorized' )
		}
		if(!isUserSuperAdmin()) {
			return renderErrorResponse(403, 'Forbidden' )
		}
		OPQuartzSchedulerService.triggerJob("Openprise check potential import anomaly scheduler job", tenantService.getSuperTenant())
		renderSuccessResponse("Success")
	}

	def cloneDS(){
		Long dsId = params.dsId as Long
		Long userId = params.userId as Long
		Long authId = params.authId as Long
		AuthType authType = params.authType as AuthType
		EventDataSource ds = eventDataSourceService.cloneDataSource(dsId, userId, authId, authType)
		render ds as JSON
	}


	def searchDataServiceStatsData(){
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		if(!isUserSuperAdmin()) {
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}

		def user = tenantService.currentUser
		EventDataSource ds = EventDataSource.findByName(DataServiceStatisticsUtils.DS_NAME)
		if(ds==null){
			render(status: 404, errors: DataServiceStatisticsUtils.DS_NAME+" Not Found") as JSON
			return
		}
		def c = AuthMethod.createCriteria()


		def authIds = c.list(params) {
			eq("isOpenpriseOwned", true)
			resultTransformer(CriteriaSpecification.ALIAS_TO_ENTITY_MAP)
			projections{
				property('id','value')

			}
		}
        if(!authIds)
            return render (["data":[], total: 0] as JSON)

        def endDate = new Date()
		def startDate
		use(TimeCategory) {
			startDate = endDate - 3.months
		}
		SimpleDateFormat formatter = new SimpleDateFormat("yyyy/MM/dd/HH/mm/ss")
		formatter.setTimeZone(TimeZone.getTimeZone("GMT"))
		startDate =formatter.format(startDate)
		endDate = formatter.format(endDate)

		def map=["tenantName":"openprise","filters":
				["left":["field":"Start Run Time","timezone":"0","values":[["from_value":startDate,"to_value":endDate]],"groupId":0,"date_format":"","operator":"date_range"],"conjunction_operator":"AND",
				 "right":["field":"Auth Method Id","values":authIds,"groupId":0,"case_sensitive":false,"operator":"equals"]]]


		def props =JsonOutput.toJson(map)

		int page = Integer.parseInt(params.page)
		int size = Integer.parseInt(params.size)

		def sortBy = "Start Run Time"
		def sortOrd =  params.sortOrder

		String sortDSAttr = "@timestamp"
		SortOrder sortOrder = SortOrder.ASC
		if(sortBy){
			sortDSAttr = dataProcessingService.getDSAttribute(ds, sortBy)
			String type = dataProcessingService.getDSAttributeType(ds, sortBy)
			// Since we are exposing @OPDedupeSurviveRecID and that will not be analyzed
			// We are adding second condition
			if(type.equalsIgnoreCase("string") && !sortDSAttr.startsWith("@OP")){
				sortDSAttr =sortDSAttr +RuleConstants.DS_ATTR_LOWERCASE_SUFFIX
			}
		}

		if(sortOrd){
			if(sortOrd.equals("asc")){
				sortOrder = SortOrder.ASC
			}
			else{
				sortOrder = SortOrder.DESC
			}
		}

		SortBuilder sortBuilder = SortBuilders.fieldSort(sortDSAttr).order(sortOrder)
		if(sortDSAttr.equals("@timestamp")){
			sortBuilder = SortBuilders.fieldSort(sortDSAttr).order(sortOrder).unmappedType("date")
		}

		SearchSourceBuilder searchSourceBuilder = dataProcessingService.getELQueryObj(ds, props, null, null, null, user)

		List list = new ArrayList<>()
        def aggData=[]
		def totalRecordsCount = 0
		try{
			Gson gson = new GsonBuilder().create();
			HashMap m = gson.fromJson( props.toString(), HashMap.class)

			int from = (page-1)*size
			def data =getParametersToBind()
			def aggregateList = data.aggregateBy

			if(aggregateList){
                aggData = aggregateData(aggregateList,sortDSAttr, searchSourceBuilder, ds)
				totalRecordsCount=aggData.size()
			}
            else{
                SearchResponse sr1 = ELKService.searchELData(searchSourceBuilder,[], size, ["from":from, "sort":sortBuilder], ds)

                java.util.Iterator<SearchHit> hit_it = sr1.getHits().iterator();
                totalRecordsCount = sr1.getHits().totalHits
				while(hit_it.hasNext()){
					SearchHit hit = hit_it.next();

					Map<String,Object> result = hit.getSourceAsMap()

					HashMap<String, String> entry = new HashMap<>();

					for(DataSourceAttribute dsAttr:ds.attributes){
						if(!dsAttr.importAttr){ // don't include attr those are not marked for import
							continue
						}
						def val
						if(dsAttr.esType!=null && dsAttr.esType.equals("nested")){

							val  = result.get(dsAttr.name)!=null?((String)(result.get(dsAttr.name).get("raw"))):null
						}
						else{
							val  = result.get(dsAttr.name)
						}

						String attr = dsAttr.originFieldName


						entry.put(attr, val);
						entry.put("@id", hit.getId())
						entry.put("@index", hit.getIndex())
					}

					//entry.put("message", message);
					list.add(entry)
				}
			}

		}catch(e){
			log.error "Failed to search elasticsearch data. Error: ${e.getMessage()}",e
			return renderErrorResponse(500, "SEARCH_FAILED", e.getMessage())
		}

		//searchSourceBuilder.set
		String elQuery = searchSourceBuilder.toString()
		JSONObject qryJSON = JSON.parse(elQuery)
		elQuery = qryJSON.get("query").toString()
		log.debug "EL Query for Search: " + elQuery

		render (["data":aggData?aggData:list, total: totalRecordsCount] as JSON)

	}

	def sendDataServiceStatsDataToDownload(){
		if(!isUserAuthorized()) {
			render(status: 401, errors: 'Unauthorized') as JSON
			return
		}
		if(!isUserSuperAdmin()) {
			render(status: 403, errors: 'Forbidden') as JSON
			return
		}

		User user = tenantService.currentUser
		def endDate = new Date()
		def startDate
		def resp=[message: "success"]
		use(TimeCategory) {
			startDate = endDate - 3.months
		}
		SimpleDateFormat formatter = new SimpleDateFormat("yyyy/MM/dd/HH/mm/ss")
		formatter.setTimeZone(TimeZone.getTimeZone("GMT"))
		def startDateStr =formatter.format(startDate)
		def endDateStr = formatter.format(endDate)
		def c = AuthMethod.createCriteria()

		def authIds = c.list(params) {
			eq("isOpenpriseOwned", true)
			resultTransformer(CriteriaSpecification.ALIAS_TO_ENTITY_MAP)
			projections{
				property('id','value')

			}
		}
		def map = ["filters":
						   ["left" : ["field": "Start Run Time", "timezone": "0", "values": [["from_value": startDateStr, "to_value": endDateStr]], "groupId": 0, "date_format": "", "operator": "date_range"], "conjunction_operator": "AND",
							"right": ["field": "Auth Method Id", "values": authIds, "groupId": 0, "case_sensitive": false, "operator": "equals"]]]


		def query =JsonOutput.toJson(map)
		def props = getParametersToBind()
		def aggregateList =props?.query?.aggregateBy
		props.put("query",query)
		EventDataSource ds = EventDataSource.findByName(DataServiceStatisticsUtils.DS_NAME)
		if(ds==null){
			render(status: 404, errors: DataServiceStatisticsUtils.DS_NAME+" Not Found") as JSON
			return
		}

		if (aggregateList) {
			def sortDSAttr = dataProcessingService.getDSAttribute(ds, "Start Run Time")
			SearchSourceBuilder searchSourceBuilder = dataProcessingService.getELQueryObj(ds, query, null, null, null, user)
			def aggData = aggregateData(aggregateList, sortDSAttr, searchSourceBuilder, ds)
			def input=[:]
			input.data = aggData
			input.downloadProps=props
			if(aggData) {
				 resp = utilityService.prepareToDownload(input,ds, user, startDate, endDate)
				render(resp as JSON)
				return
			}
			else
			render(status: 404, errors: 'empty data') as JSON
			return
		}
		else if(!eventDataSourceService.prepareDataToDownloadUpdated(props , ds.id , null , user)){
			render(status: 503, errors: 'service not available') as JSON
			return
		}

		render(resp as JSON)

	}

	private def aggregateData(def aggregateList,def sortDSAttr, SearchSourceBuilder searchSourceBuilder, EventDataSource ds) {
        AbstractAggregationBuilder agg
        def data = []

        try {
            DateHistogramInterval intervalVal
            if (aggregateList.contains("Year")) {
                intervalVal = DateHistogramInterval.YEAR
                if (aggregateList.contains("Month"))
                    aggregateList.remove("Month")
            } else if (aggregateList.contains("Month")) {
                intervalVal = DateHistogramInterval.MONTH
            }

            if (intervalVal)
                agg = AggregationBuilders.dateHistogram("Start Run Time")
                        .field(sortDSAttr).order(BucketOrder.key(false))
                        .dateHistogramInterval(intervalVal)

			def apiCallsList = ["Successful API calls",
								"Results with data", "API Calls", "Failed API Calls", "Total Records", "Average Records"]

			def aggClosure = { aggList ->
                boolean addedCalls = false
                def newAgg
                aggList.each { String key ->
                    if (key != "Year" && key != "Month") {
						String termField =dataProcessingService.getDSAttribute(ds, key)?:""
						if (!newAgg) {
							newAgg = AggregationBuilders.terms(key)
									.field(termField)

							apiCallsList.each { fName ->
								def fieldName = dataProcessingService.getDSAttribute(ds, fName)
								if (fieldName)
									newAgg = newAgg.subAggregation(AggregationBuilders.sum(fName).field(fieldName))
							}
						} else {
							newAgg = AggregationBuilders.terms(key)
									.field(termField).subAggregation(newAgg)
						}
					}

                }
                if (agg) {
                    if (newAgg)
                        agg = agg.subAggregation(newAgg)
                    else {
						apiCallsList.each { fName ->
							def fieldName = dataProcessingService.getDSAttribute(ds, fName)
							if (fieldName)
								agg = agg.subAggregation(AggregationBuilders.sum(fName).field(fieldName))
						}
                    }
                } else {
                    if (newAgg)
                        agg = newAgg
                }
            }
            aggClosure(aggregateList)
            SearchResponse sr1 = ELKService.searchELData(searchSourceBuilder, agg ? [agg] : [], 0, null, ds)

            def addBuckets
            def addAgg

            addBuckets = { bks, key, qp ->
                for (def buck : bks) {
                    def mapClone = qp.clone()
                    if (buck) {
                        mapClone.put(key, buck?.getKey())
                        def ag = buck?.getAggregations()?.asMap()
                        if (ag) {
                            addAgg(ag, mapClone)
                        }
                    }
                }
            }
            addAgg = { ag, qp ->
                def addData = false
                ag.each { key, val ->
                    if (key in apiCallsList) {
						addData = true
                        qp.put(key, val.getValue())
                    } else {
                        if (val.buckets)
                            addBuckets(val.buckets, key, qp)
                        else data.add(qp)

                    }
                }
                if (addData)
                    data.add(qp)

            }
			def aggsMap = sr1?.getAggregations()?.asMap()
			aggsMap?.each { key, val ->
				def buks = val.buckets

				for (def buk : buks) {
					def mp = [:]
					mp.put(key, buk.getKey().toString())
					def ag = buk?.getAggregations()?.asMap()
					if (ag) {
						addAgg(ag, mp)
					} else
						data.add(mp)
				}
			}
        } catch (Exception e) {
            log.error("Error while getting data from elasticsearch :" + e.getMessage(), e)
        }
        return data
    }


}
